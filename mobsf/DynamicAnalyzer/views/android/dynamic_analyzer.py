# -*- coding: utf_8 -*-

"""Android Dynamic Analysis."""
import logging
import os
import time
import subprocess
from pathlib import Path
from json import dump
import json
import requests
from shelljob import proc
import threading

from django.http import (HttpResponseRedirect,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render
from django.db.models import ObjectDoesNotExist

from mobsf.DynamicAnalyzer.views.android.tests_frida import instrument

from mobsf.DynamicAnalyzer.views.android import operations, tests_common
# from tests_common import activity_tester
from mobsf.DynamicAnalyzer.views.android.environment import (
    ANDROID_API_SUPPORTED,
    Environment,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    start_httptools_ui,
    stop_httptools,
)
from mobsf.MobSF.utils import (
    get_android_dm_exception_msg,
    get_config_loc,
    get_device,
    get_proxy_ip,
    is_md5,
    print_n_send_error_response,
    python_list,
    python_dict,
    strict_package_check,
    api_key,
)
from mobsf.MobSF.views.scanning import add_to_recent_scan
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)
from EmulatorLauncher import *
# from tests_frida import instrument
from mobsf.DynamicAnalyzer.views.android.queue import *

logger = logging.getLogger(__name__)

analysis_queue = None
queue_display = []
current_live = [{'identifier': 'TESTINGDATA', 'checksum': 'TESTINGDATA'}]

# Get MOBSF path from ENV
mobsf_path = os.environ.get('MOBSF_PATH') 

# Utilizing path for Frida
directory_path = os.path.join(mobsf_path, 'mobsf/DynamicAnalyzer/tools/frida_scripts/android/others')

mappings_path = Path('mobsf/DynamicAnalyzer/views/android/permission_mappings.json')

try:
    with mappings_path.open('r', encoding='utf-8') as permission_map:
        permission_mappings = json.load(permission_map)

except FileNotFoundError:
    print("Error: Config file not found.")
    permission_mappings = {}
except json.JSONDecodeError as e:
    print(f"Error: JSON decode error - {e}")
    permission_mappings = {}

PERMISSION_GROUPS = permission_mappings.get('PERMISSION_GROUPS', {})
API_GROUPS = permission_mappings.get('API_GROUPS', {})
PLAYSTOREINFORMATION_GROUPS = permission_mappings.get('PLAYSTOREINFORMATION_GROUPS', {})

if not PERMISSION_GROUPS:
    print("Warning: PERMISSION_GROUPS not loaded.")
if not API_GROUPS:
    print("Warning: API_GROUPS not loaded.")
if not PLAYSTOREINFORMATION_GROUPS:
    print("Warning: PLAYSTOREINFORMATION_GROUPS not loaded.")

def permisions_to_script(static_android_db, selectedscript):
       try:
           permissions = python_list(static_android_db.PERMISSIONS)
           #print(permissions)
           permissionlist = []
           for i in permissions:
               permissionlist.append(i)


           selectedscript = select_frida_script_permissions(permissions)


           if len(selectedscript) == 0:
               selectedscript = selectedscript
           else:
               selectedscript = selectedscript + selectedscript
           return selectedscript
       except ObjectDoesNotExist:
           return 'error'




def api_to_script(static_android_db, selectedscript):
       try:
           androidapis = eval(static_android_db.ANDROID_API)
           keys = androidapis.keys()
           keys_list = list(keys)
           selectedscript = select_frida_script_androidapis(keys_list)
           if len(selectedscript) == 0:
               selectedscript = selectedscript
           else:
               selectedscript = selectedscript + selectedscript
           return selectedscript
       except ObjectDoesNotExist:
           return 'error'


def dex_to_script(static_android_db, selectedscript):
       try:
           dex = static_android_db.APKID
           if len(dex) > 0:
               if 'DEX_dex.js' not in selectedscript:
                   selectedscript.append('DEX_dex.js')
           return selectedscript
       except ObjectDoesNotExist:
            return 'error'
       except:
            return []


def playstore_to_script(static_android_db, selectedscript):
       try:
           playstoredetails = python_dict(static_android_db.PLAYSTORE_DETAILS)
           if playstoredetails:
               results = find_matching_js_files(playstoredetails['description'], PLAYSTOREINFORMATION_GROUPS)
               for files in results:
                   selectedscript.append(files)
           return selectedscript
       except ObjectDoesNotExist:
            return 'error'
       except:
            return []


def cut_string(input_string):
    index = input_string.find('_')
    if index != -1:
        result = input_string[:index]
        return result
    else:
        pass

def combine_dicts(*dicts):
    combined_dict = {}
    for d in dicts:
        combined_dict.update(d)
    return combined_dict

def map_permissions_to_group(permission):
    parts = permission.split('.')
    permission_name = parts[-1]
    for group, permissions in PERMISSION_GROUPS.items():
        if permission_name in permissions:
            return group
        else:
            for items in permissions:
                if items in permission_name:
                    return group
    return None

def select_frida_script_permissions(permissions):
    scripts = []
    for permission in permissions:
        group = map_permissions_to_group(permission)
        if group:
            for filename in os.listdir(directory_path):
                if cut_string(filename) == group:
                    if filename in scripts:
                        pass
                    else:
                        scripts.append(filename)
    return scripts

# API Groups
def map_api_to_group(androidapi):
    for group, androidapis in API_GROUPS.items():
        if androidapi in androidapis:
            return group
    return None

def select_frida_script_androidapis(androidapis):
    scripts = []
    for androidapi in androidapis:
        group = map_api_to_group(androidapi)
        if group:
            for filename in os.listdir(directory_path):
                if cut_string(filename) == group:
                    if filename in scripts:
                        pass
                    else:
                        scripts.append(filename)
    return scripts

def get_available_emulators():
    emulator_command = ["emulator", "-list-avds"]
    process = subprocess.Popen(emulator_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output, _ = process.communicate()
    emulator_names = output.strip().split('\n')[1:]  # Exclude the first line
    return emulator_names

def get_emulator_names(emulatorid_list):
    dict = {}
    for emulatorid in emulatorid_list:
        command = ["adb", "-s", emulatorid, "emu", "avd", "name"]
        result = subprocess.run(command, capture_output=True, text=True)
        emulator_name = result.stdout.strip().splitlines()[0]
        dict[emulatorid] = emulator_name
    return dict

def find_key_by_value(dictionary, value):
    for key, val in dictionary.items():
        if val == value:
            return key
    return None

def check_repeated_identifiers(data):
    identifiers = set()
    repeated_identifiers = set()
    
    for item in data:
        identifier = item['identifier']
        if identifier in identifiers:
            repeated_identifiers.add(identifier)
        else:
            identifiers.add(identifier)
    
    return repeated_identifiers

def find_position(data, search_item):
    position = None
    for i, item in enumerate(data):
        if item == search_item:
            position = i
            break
    return position

def check_identifiers(data, currentlive):
    data_identifier = data[0]['identifier']
    for item in currentlive:
        if item['identifier'] == data_identifier:
            return data[0]
    return None

def remove_by_identifier(identifier):
    global current_live
    current_live = [item for item in current_live if item['identifier'] != identifier]

def find_matching_js_files(paragraph: str, keyword_groups: dict) -> list:
    # Convert the paragraph to lowercase to ensure case-insensitive matching
    paragraph_lower = paragraph.lower()
    # Initialize a list to store the matching .js filenames
    matching_js_files = []
    # Iterate through the keyword groups
    for js_file, keywords in keyword_groups.items():
        # Check if any of the keywords are found in the paragraph
        for keyword in keywords:
            if keyword in paragraph_lower:
                matching_js_files.append(js_file)
                break  # Break the inner loop if a match is found to avoid duplicate entries
    return matching_js_files

def change_status(data, identifier, checksum, new_status):
    for item in data:
        if item.get('identifier') == identifier and item.get('checksum') == checksum:
            item['status'] = new_status
            break

@login_required
@permission_required(Permissions.SCAN)
def android_dynamic_analysis(request, api=False):
    """Android Dynamic Analysis Entry point."""
    try:
        scan_apps = []
        device_packages = {}
        and_ver = None
        and_sdk = None
        apks = StaticAnalyzerAndroid.objects.filter(
            APP_TYPE='apk')
        identifier = None

        for apk in reversed(apks):
            logcat = Path(settings.UPLD_DIR) / apk.MD5 / 'logcat.txt'
            temp_dict = {
                'ICON_PATH': apk.ICON_PATH,
                'MD5': apk.MD5,
                'APP_NAME': apk.APP_NAME,
                'VERSION_NAME': apk.VERSION_NAME,
                'FILE_NAME': apk.FILE_NAME,
                'PACKAGE_NAME': apk.PACKAGE_NAME,
                'DYNAMIC_REPORT_EXISTS': logcat.exists(),
                'PERMISSIONS': apk.PERMISSIONS,
                'DEX': apk.APKID,
                'ANDROIDAPI': apk.ANDROID_API
            }
            scan_apps.append(temp_dict)
        try:
            devicesidentified = get_device()
            #print(devicesidentified)
        except Exception:
            return print_n_send_error_response(
                request, get_android_dm_exception_msg(), api)
        try:
            dicts = []
            combined = {}

            appsdict = {}
            identifierdict = {}
            android_versiondict = {}
            android_sdkdict = {}
            android_supporteddict = {}
            proxy_ipdict = {}
            proxy_portdict = {}
            settings_locdict = {}
            device_packagesdict = {}
            titledict = {}
            versiondict = {}
            for i in range(len(devicesidentified)):
                identifier = devicesidentified[i-1]
                if identifier:
                    env = Environment(identifier)
                    env.connect()
                    device_packages = env.get_device_packages()
                    #print(device_packages)
                    dicts.append(device_packages)
                    and_ver = env.get_android_version()
                    and_sdk = env.get_android_sdk()
                    appsdict[identifier] = scan_apps
                    identifierdict[identifier] = identifier
                    android_versiondict[identifier] = and_ver
                    android_sdkdict[identifier] = and_sdk
                    android_supporteddict[identifier] = ANDROID_API_SUPPORTED
                    proxy_ipdict[identifier] = get_proxy_ip(identifier)
                    proxy_portdict[identifier] = settings.PROXY_PORT
                    settings_locdict[identifier] = get_config_loc()
                    device_packagesdict[identifier] = device_packages
                    titledict[identifier] = 'MobSF Dynamic Analysis'
                    versiondict[identifier] = settings.MOBSF_VER
                    # deviceinformation['apps'] = scan_apps
                    # deviceinformation['identifier'] = identifier
                    # deviceinformation['android_version'] = and_ver
                    # deviceinformation['android_sdk'] = and_sdk
                    # deviceinformation['android_supported'] = ANDROID_API_SUPPORTED
                    # deviceinformation['proxy_ip'] = get_proxy_ip(identifier)
                    # deviceinformation['proxy_port'] = settings.PROXY_PORT
                    # deviceinformation['settings_loc'] = get_config_loc()
                    # deviceinformation['device_packages'] = device_packages
                    # deviceinformation['title'] = 'MobSF Dynamic Analysis'
                    # deviceinformation['version'] = settings.MOBSF_VER
                    # context['emulator5556'] = deviceinformation

            for d in dicts:
                combined.update(d)
            if combined:
                pkg_file = Path(settings.DWD_DIR) / 'packages.json'
                with pkg_file.open('w', encoding='utf-8') as target:
                    dump(combined, target)
#                    summarydevicepackages[identifier] = device_packages
#            print(summarydevicepackages)
        except Exception:
            pass
        context = {'apps': scan_apps,
                    'identifier': identifierdict,
                    'android_version': android_versiondict,
                    'android_sdk': android_sdkdict,
                    'android_supported': ANDROID_API_SUPPORTED,
                    'proxy_ip': proxy_ipdict,
                    'proxy_port': proxy_portdict,
                    'settings_loc': get_config_loc(),
                    'device_packages': device_packagesdict,
                    'title': 'MobSF Dynamic Analysis',
                    'version': settings.MOBSF_VER
                    }
        #print(context)
        if api:
            return context
        template = 'dynamic_analysis/android/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis')
        return print_n_send_error_response(request, exp, api)
    
def persistent_function():
    if not hasattr(persistent_function, 'has_run'):
        result = "0"
        persistent_function.has_run = True
    else:
        # Subsequent behavior
        result = "1"
    
    return result

lock = threading.Lock()

@login_required
@permission_required(Permissions.SCAN)
def dynamic_analyzer(request, checksum, api=False, avd_name=None):
    """Android Dynamic Analyzer Environment."""
    file_list_without_extension = []
    text = ""
    apiKey = api_key()
    
    try:
        identifier = None
        activities = None
        exported_activities = None
        if api:
            reinstall = request.POST.get('re_install', '1')
            install = request.POST.get('install', '1')
            avd_name = request.POST.get('avd_name', None)
        else:
            reinstall = request.GET.get('re_install', '1')
            install = request.GET.get('install', '1')
            avd_name = request.GET.get('avd_name', None)
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Cannot get package name from checksum',
                api)
        logger.info('Creating Dynamic Analysis Environment for %s', package)
        # Auto-start and auto-stop emulator logic
        avds = list_avds()
        logger.info(f"Available AVDs: {avds}")
        running_emulators = list_running_emulators()
        logger.info(f"Running Emulators: {running_emulators}")
        running_avds = {get_avd_name(emulator): emulator for emulator in running_emulators}
        logger.info(f"Running AVDs: {running_avds}")

        emulator_started = False
        if avd_name:
            selected_avd = avd_name
        else:
            selected_avd = avds[0]
            emulator_started = True
            
        if not selected_avd:
            msg = 'No AVD specified and no AVDs are available. Here are the available AVDs: '
            msg += ', '.join(avds) if avds else 'None'
            if api:
                return {'error': msg, 'available_avds': avds}
            else:
                return print_n_send_error_response(request, msg, api)

        if selected_avd not in running_avds:
            logger.info(f"Starting emulator for AVD: {selected_avd}")
            start_emulator(selected_avd)
            emulator_started = True

        if not emulator_started:
            identifier = get_device()
        else:
            # Wait for the emulator to be recognized by ADB
            time.sleep(30)
            identifier = get_device()

        # Get activities from the static analyzer results
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            exported_activities = python_list(
                static_android_db.EXPORTED_ACTIVITIES)
            activities = python_list(
                static_android_db.ACTIVITIES)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')

        # Get permissions from the static analyzer results
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            permissions = python_list(static_android_db.PERMISSIONS)
            #print(permissions)
            permissionlist = []
            for i in permissions:
                permissionlist.append(i)
            selectedscript = select_frida_script_permissions(permissions)
            if len(selectedscript) == 0:
                selectedscript = selectedscript
            else:
                selectedscript = selectedscript + selectedscript
            #print(selectedscript)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Permissions. '
                'Static Analysis not completed for the app.')
            
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            androidapis = eval(static_android_db.ANDROID_API)
            keys = androidapis.keys()
            keys_list = list(keys)
            selectedscript = select_frida_script_androidapis(keys_list)
            if len(selectedscript) == 0:
                selectedscript = selectedscript
            else:
                selectedscript = selectedscript + selectedscript
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Android API. '
                'Static Analysis not completed for the app.')
            
        try:
            dex = static_android_db.APKID
            if len(dex) > 0:
                if 'DEX_dex.js' not in selectedscript:
                    selectedscript.append('DEX_dex.js')
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Dex Files. '
                'Static Analysis not completed for the app.')
        except:
            pass

        try:
            playstoredetails = python_dict(
                static_android_db.PLAYSTORE_DETAILS)
            if playstoredetails:
                results = find_matching_js_files(playstoredetails['description'])
                for files in results:
                    selectedscript.append(files)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get playstore details. '
                'Static Analysis not completed for the app.')
        except:
            pass

        try: 
            #
            selectedscript = list(set(selectedscript))
            #print(selectedscript)
            for scripts in selectedscript:
                textsuggest = textsuggest + '\n // ' + scripts 

            for scripts in selectedscript:
                file_path = '{}'.format(scripts)
                try:
                    with open(file_path, 'r') as file:
                            texting = file.read()
                            textscripts = textscripts + '\n\n' + texting
                except FileNotFoundError:
                    print("File not found:", file_path)
                except Exception as e:
                    print("Error:", e)
                file_list_without_extension = [filename.replace('.js', '') for filename in selectedscript]

            text = textsuggest + textscripts
        except:
            pass
        
        env = Environment(identifier)
        if not env.connect_n_mount():
            msg = 'Cannot Connect to ' + identifier
            return print_n_send_error_response(request, msg, api)
        version = env.get_android_version()
        logger.info('Android Version identified as %s', version)
        xposed_first_run = False
       
        if not env.is_mobsfyied(version):
            msg = ('This Android instance is not MobSFyed/Outdated.\n'
                   'MobSFying the android runtime environment')
            logger.warning(msg)
            if not env.mobsfy_init():
                return print_n_send_error_response(
                    request,
                    'Failed to MobSFy the instance',
                    api)
            if version < 5:
                # Start Clipboard monitor
                env.start_clipmon()
                xposed_first_run = True
        if xposed_first_run:
            msg = ('Have you MobSFyed the instance before'
                   ' attempting Dynamic Analysis?'
                   ' Install Framework for Xposed.'
                   ' Restart the device and enable'
                   ' all Xposed modules. And finally'
                   ' restart the device once again.')
            return print_n_send_error_response(request, msg, api)
        # Clean up previous analysis
        env.dz_cleanup(checksum)
        # Configure Web Proxy
        env.configure_proxy(package, request)
        # Supported in Android 5+
        env.enable_adb_reverse_tcp(version)
        # Apply Global Proxy to device
        env.set_global_proxy(version)
        if install == '1':
            # Install APK
            apk_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.apk'
            status, output = env.install_apk(
                apk_path.as_posix(),
                package,
                reinstall)
            if not status:
                # Unset Proxy
                env.unset_global_proxy()
                msg = (f'This APK cannot be installed. Is this APK '
                       f'compatible the Android VM/Emulator?\n{output}')
                return print_n_send_error_response(
                    request,
                    msg,
                    api)
        logger.info('Testing Environment is Ready!')
        lock.acquire()
        
        if request.POST.get('cmd'):
            adb_command_result = env.adb_command(request['cmd'])
            cmd_str= request['cmd']
        else:
            adb_command_result = "Not called."
            cmd_str = "Not called."
            pass

        #env.install_mobsf_ca(request['adb_command_action'])
        if request.POST.get('global_proxy_action') == 'unset':
            env.unset_global_proxy()
        else:
            pass
        
        headers = {
            'X-Mobsf-Api-Key': api_key()
        }

        activity_data = {
        'test': 'exported', 
        'deviceidentifier': identifier,
        'hash': checksum,
        }

        tls_data = {
            'hash': checksum,
            'deviceidentifier': identifier,
        }

        recommend_data = {
            'hash': checksum
        }

        activity_url = f"{request.scheme}://{request.get_host()}/api/v1/android/activity"
        activity_result = requests.post(activity_url, data=activity_data, headers=headers)  
        if activity_result.status_code == 200:
            activity_result = activity_result.json()
            logger.info('Activity test successful')
        else:
            activity_result = "Failed"
            logger.error(f'Activity test failed')

        tls_url = f"{request.scheme}://{request.get_host()}/api/v1/android/tls_tests"
        try:
            response = requests.post(tls_url, data=tls_data, headers=headers)
            if response.status_code == 200:
                try:
                    tls_result = response.json()
                    logger.info('TLS test successful')
                    print("Success:", tls_result)
                except requests.exceptions.JSONDecodeError:
                    logger.error("Error: Received response is not in JSON format")
                    print("Error: Received response is not in JSON format")
                    print(response.text)
                    tls_result = "Error: Invalid JSON response"
            else:
                logger.error(f'TLS test failed with status code: {response.status_code}')
                print(f'TLS test failed with status code: {response.status_code}')
                tls_result = f"Failed with status code: {response.status_code}"
        except requests.RequestException as e:
            logger.error(f"An error occurred: {e}")
            print(f"An error occurred: {e}")
            tls_result = f"Request failed: {str(e)}"


        recommend_url = f"{request.scheme}://{request.get_host()}/api/v1/frida/recommend"

        recommendations_response = requests.post(recommend_url, data=recommend_data, headers=headers)

        if recommendations_response.status_code == 200:
            recommendations = recommendations_response.json()
            if recommendations["status"] == "ok":
                recommended_scripts = recommendations["recommended scripts"]


        if persistent_function() == "0":
            logger.info('Starting Frida Instrumentation...')
        
        else:
            logger.info("Waiting for existing Frida instrumentation to complete.")

        
        logger.info('Waiting 5 seconds.')
        time.sleep(5)
        default_hooks = request.POST.get('default_hooks', 'api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass')
        auxiliary_hooks = request.POST.get('auxiliary_hooks', 'enum_class,string_catch,string_compare,enum_methods,search_class,trace_class')
        others = request.POST.get('others', ",".join(recommended_scripts))
        frida_code = request.POST.get('frida_code', '"Java.perform(function()+%7B%0A++%2F%2F+Use+send()+for+logging%0A%7D)%3B"')
        #frida calls
        frida_instrument_url = f"{request.scheme}://{request.get_host()}/api/v1/frida/instrument"
        frida_data = {
            'hash': checksum,
            'default_hooks': default_hooks,
            'auxiliary_hooks': auxiliary_hooks,
            "others_scripts": others,
            'frida_code': frida_code,
            'deviceidentifier': identifier,
            'frida_action': 'spawn'
            
        }
        
        # Make the API call with headers
        frida_response = requests.post(frida_instrument_url, data=frida_data, headers=headers)   
        logger.info('Waiting for Frida instrumentation..')
        #time.sleep(15) # change this
        if frida_response.status_code == 200:
            logger.info('Frida instrumentation successful')
        else:
            logger.error(f'Frida instrumentation failed: {frida_response.text}')
        
        all_hooks = default_hooks + ',' + auxiliary_hooks + ',' + ",".join(recommended_scripts)
        hooks_list = all_hooks.split(',')
        lock.release()
        context = {'package': package,
                   'hash': checksum,
                   'api_key': apiKey,
                   'android_version': version,
                   'version': settings.MOBSF_VER,
                   'activities': activities,
                   'exported_activities': exported_activities,
                   'title': 'Dynamic Analyzer',
                   'text': text,
                   'scripts': hooks_list,
                   'device_used': selected_avd,
                   'cmd': cmd_str,
                   'cmd_result': adb_command_result,
                   'activity_result': activity_result,
                   'tls_result': tls_result,
                    }
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        if api:
            return context
        return render(request, template, context)
        

    except TimeoutError as e:
        logger.error(f"Dynamic analysis timed out for checksum {checksum}: {e}")
        return print_n_send_error_response(request, "Dynamic analysis timed out", api)

    except Exception:
        logger.exception('Dynamic Analyzer')
        return print_n_send_error_response(request, 'Dynamic Analysis Failed.', api)


@login_required
@permission_required(Permissions.SCAN)
def httptools_start(request):
    """Start httprools UI."""
    logger.info('Starting httptools Web UI')
    try:
        httptools_url = get_http_tools_url(request)
        stop_httptools(httptools_url)
        start_httptools_ui(settings.PROXY_PORT)
        time.sleep(3)
        logger.info('httptools UI started')
        if request.GET['project']:
            project = request.GET['project']
        else:
            project = ''
        url = f'{httptools_url}/dashboard/{project}'
        return HttpResponseRedirect(url)
    except Exception:
        logger.exception('Starting httptools Web UI')
        err = 'Error Starting httptools UI'
        return print_n_send_error_response(request, err)


@login_required
@permission_required(Permissions.SCAN)
def logcat(request, api=False):
    logger.info('Starting Logcat streaming')
    try:
        pkg = request.GET.get('package')
        device = request.GET.get('device')
        print(device)
        if pkg:
            if not strict_package_check(pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            template = 'dynamic_analysis/android/logcat.html'
            return render(request, template, {'package': pkg, 'device' : device})
        if api:
            app_pkg = request.POST['package']
        else:
            app_pkg = request.GET.get('app_package')
        if app_pkg:
            if not strict_package_check(app_pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            adb = os.environ['MOBSF_ADB']
            g = proc.Group()
            print(adb)
            print(device)
            g.run([adb, '-s', device, 'logcat', app_pkg + ':V', '*:*'])
            def read_process():
                while g.is_pending():
                    lines = g.readlines()
                    for _, line in lines:
                        print(line)
                        yield 'data:{}\n\n'.format(line)
            return StreamingHttpResponse(read_process(),
                                         content_type='text/event-stream')
        return print_n_send_error_response(
            request,
            'Invalid parameters',
            api)
    except Exception:
        logger.exception('Logcat Streaming')
        err = 'Error in Logcat streaming'
        return print_n_send_error_response(request, err, api)


@login_required
@permission_required(Permissions.SCAN)
def trigger_static_analysis(request, checksum):
    """On device APK Static Analysis."""
    try:
        identifier = None
        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                'Invalid MD5')
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Cannot get package name from checksum')
        try:
            identifier = get_device()
        except Exception:
            err = 'Cannot connect to Android Runtime'
            return print_n_send_error_response(request, err)
        env = Environment(identifier)
        apk_file = env.get_apk(checksum, package)
        if not apk_file:
            err = 'Failed to download APK file'
            return print_n_send_error_response(request, err)
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': checksum,
            'scan_type': 'apk',
            'file_name': f'{package}.apk',
        }
        add_to_recent_scan(data)
        return HttpResponseRedirect(f'/static_analyzer/{checksum}/')
    except Exception:
        msg = 'On device APK Static Analysis'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)
    
def android_dynamic_analysis_appsavailable(request, api=False):
    """Android Dynamic Analysis Entry point."""
    try:
        emulator_list = get_available_emulators()
        scan_apps = []
        apks = StaticAnalyzerAndroid.objects.filter(
            APP_TYPE='apk')

        for apk in reversed(apks):
            logcat = Path(settings.UPLD_DIR) / apk.MD5 / 'logcat.txt'
            temp_dict = {
                'ICON_PATH': apk.ICON_PATH,
                'MD5': apk.MD5,
                'APP_NAME': apk.APP_NAME,
                'VERSION_NAME': apk.VERSION_NAME,
                'FILE_NAME': apk.FILE_NAME,
                'PACKAGE_NAME': apk.PACKAGE_NAME,
                'DYNAMIC_REPORT_EXISTS': logcat.exists(),
                'PERMISSIONS': apk.PERMISSIONS,
                'DEX': apk.APKID,
                'ANDROIDAPI': apk.ANDROID_API
            }
            scan_apps.append(temp_dict)
        if len(queue_display) != None:
            displaystuff = queue_display
        else:
            displaystuff = []
        context = {'apps': scan_apps,
                    'title': 'MobSF Dynamic Analysis',
                    'version': settings.MOBSF_VER,
                    'emulator_list': emulator_list,
                    'queuedisplay': displaystuff
                    }
        if api:
            return context
        template = 'dynamic_analysis/android/dynamic_analysis_appsavailable.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis Apps Available')
        return print_n_send_error_response(request, exp, api)



def dynamic_analyzer_appsavailable(request, checksum, identifier, api=False):
    """Android Dynamic Analyzer Environment."""
    itemdata = {'identifier': identifier,'checksum': checksum}
    
    global analysis_queue
    global queue_display
    global current_live
    if analysis_queue is None:
        analysis_queue = Queue()
        analysis_queue.enqueue({'identifier': identifier,'checksum': checksum})
        queue_display.append({'identifier': identifier,'checksum': checksum, 'status':'PENDING, IN-QUEUE'})
    else:
        analysis_queue.enqueue({'identifier': identifier,'checksum': checksum})
        queue_display.append({'identifier': identifier,'checksum': checksum, 'status':'PENDING, IN-QUEUE'})
    print(analysis_queue.get_content())

    print(find_position(analysis_queue.get_content(), itemdata))
    
    #position = find_position(analysis_queue.get_content(), itemdata)
    #repeated_identifiers = check_repeated_identifiers(analysis_queue)

    print(current_live)
    print(analysis_queue.get_content())
    print(current_live)
    print(analysis_queue.get_content())
    print(current_live)
    print(analysis_queue.get_content())
    print(current_live)

    # while find_position(analysis_queue.get_content(), itemdata) != 0:
    #     print('waiting')
    #     time.sleep(1)

    # if len(current_live) != 0:
    #     while check_identifiers(analysis_queue.get_content(), current_live):
    #         thingtomove = check_identifiers(analysis_queue.get_content(), current_live)
    #         analysis_queue.move_to_last(thingtomove)
    #         print(analysis_queue.get_content())
    #         print(analysis_queue.get_content())
    #         print(analysis_queue.get_content())    

    while find_position(analysis_queue.get_content(), itemdata) != 0 or check_identifiers(analysis_queue.get_content(), current_live):
        time.sleep(2)
        var = check_identifiers(analysis_queue.get_content(), current_live)
        if var != None:
            print(var)
            analysis_queue.move_to_last(var)
        print(current_live)
        print(analysis_queue.get_content())
        # print('waiting')
        time.sleep(1)

    # if len(current_live) != 0:
    #     while check_identifiers(analysis_queue.get_content(), current_live):
    #         thingtomove = check_identifiers(analysis_queue.get_content(), current_live)
    #         analysis_queue.move_to_last(thingtomove)
    #         print(analysis_queue.get_content())
    #         print(analysis_queue.get_content())
    #         print(analysis_queue.get_content())    
    try:
        print(checksum)
        print(identifier)
        start_emulator(identifier)
        time.sleep(30)
        emulatorid_list = get_device()
        dict = get_emulator_names(emulatorid_list)
        apiKey = api_key()
    except:
        print('error, removing it from queue')
        analysis_queue.dequeue()
    try:
        value = find_key_by_value(dict, identifier)
        deviceidentifier = value
        #print(identifier)
        activities = None
        exported_activities = None
        textsuggest = ' // The suggested Frida scripts for dynamic analysis are: '
        textscripts = ' '
        file_list_without_extension = []
        selectedscript = []
        if api:
            reinstall = request.POST.get('re_install', '1')
            install = request.POST.get('install', '1')
        else:
            reinstall = request.GET.get('re_install', '1')
            install = request.GET.get('install', '1')
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Cannot get package name from checksum',
                api)
        logger.info('Creating Dynamic Analysis Environment for %s', package)
        try:
            #identifier = get_device()
            identifier = deviceidentifier
            command = ["adb", "-s", identifier, "emu", "avd", "name"]
            result = subprocess.run(command, capture_output=True, text=True)
            emulator_name = result.stdout.strip().splitlines()[0]
            print(emulator_name)
        except Exception:
            return print_n_send_error_response(
                request, get_android_dm_exception_msg(), api)

        # Get activities from the static analyzer results
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            exported_activities = python_list(
                static_android_db.EXPORTED_ACTIVITIES)
            activities = python_list(
                static_android_db.ACTIVITIES)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')

        # Get permissions from the static analyzer results
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            permissions = python_list(static_android_db.PERMISSIONS)
            #print(permissions)
            permissionlist = []
            for i in permissions:
                permissionlist.append(i)
            print(permissionlist)
            selectedscript = select_frida_script_permissions(permissions)
            if len(selectedscript) == 0:
                selectedscript = selectedscript
            else:
                selectedscript = selectedscript + selectedscript
            #print(selectedscript)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Permissions. '
                'Static Analysis not completed for the app.')
            
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            androidapis = eval(static_android_db.ANDROID_API)
            keys = androidapis.keys()
            keys_list = list(keys)
            selectedscript = select_frida_script_androidapis(keys_list)
            if len(selectedscript) == 0:
                selectedscript = selectedscript
            else:
                selectedscript = selectedscript + selectedscript
            print(selectedscript)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Android API. '
                'Static Analysis not completed for the app.')
            
        try:
            dex = static_android_db.APKID
            if len(dex) > 0:
                if 'DEX_dex.js' not in selectedscript:
                    selectedscript.append('DEX_dex.js')
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Dex Files. '
                'Static Analysis not completed for the app.')
        except:
            pass

        try:
            playstoredetails = python_dict(
                static_android_db.PLAYSTORE_DETAILS)
            if playstoredetails:
                results = find_matching_js_files(playstoredetails['description'], PLAYSTOREINFORMATION_GROUPS)
                for files in results:
                    selectedscript.append(files)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get playstore details. '
                'Static Analysis not completed for the app.')
        except:
            pass

        try: 
            selectedscript = list(set(selectedscript))
            #print(selectedscript)
            for scripts in selectedscript:
                textsuggest = textsuggest + '\n // ' + scripts 

            for scripts in selectedscript:
                file_path = os.path.join(mobsf_path, 'mobsf/DynamicAnalyzer/tools/frida_scripts/android/others{}'.format(scripts))
                try:
                    with open(file_path, 'r') as file:
                            texting = file.read()
                            textscripts = textscripts + '\n\n' + texting
                except FileNotFoundError:
                    print("File not found:", file_path)
                except Exception as e:
                    print("Error:", e)
                file_list_without_extension = [filename.replace('.js', '') for filename in selectedscript]

            text = textsuggest + textscripts
        except:
            pass

        env = Environment(identifier)
        if not env.connect_n_mount():
            msg = 'Cannot Connect to ' + identifier
            return print_n_send_error_response(request, msg, api)
        version = env.get_android_version()
        logger.info('Android Version identified as %s', version)
        xposed_first_run = False
        if not env.is_mobsfyied(version):
            msg = ('This Android instance is not MobSFyed/Outdated.\n'
                   'MobSFying the android runtime environment')
            logger.warning(msg)
            if not env.mobsfy_init():
                return print_n_send_error_response(
                    request,
                    'Failed to MobSFy the instance',
                    api)
            if version < 5:
                # Start Clipboard monitor
                env.start_clipmon()
                xposed_first_run = True
        if xposed_first_run:
            msg = ('Have you MobSFyed the instance before'
                   ' attempting Dynamic Analysis?'
                   ' Install Framework for Xposed.'
                   ' Restart the device and enable'
                   ' all Xposed modules. And finally'
                   ' restart the device once again.')
            return print_n_send_error_response(request, msg, api)
        # Clean up previous analysis
        env.dz_cleanup(checksum)
        # Configure Web Proxy
        env.configure_proxy(package, request)
        # Supported in Android 5+
        env.enable_adb_reverse_tcp(version)
        # Apply Global Proxy to device
        env.set_global_proxy(version)
        if install == '1':
            # Install APK
            apk_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.apk'
            status, output = env.install_apk(
                apk_path.as_posix(),
                package,
                reinstall)
            if not status:
                # Unset Proxy
                env.unset_global_proxy()
                msg = (f'This APK cannot be installed. Is this APK '
                       f'compatible the Android VM/Emulator?\n{output}')
                return print_n_send_error_response(
                    request,
                    msg,
                    api)
        logger.info('Testing Environment is Ready!')
        print(file_list_without_extension)
        context = {'package': package,
                   'hash': checksum,
                   'api_key': apiKey,
                   'android_version': version,
                   'version': settings.MOBSF_VER,
                   'activities': activities,
                   'exported_activities': exported_activities,
                   'title': 'Dynamic Analyzer',
                   'text': text,
                   'scripts': file_list_without_extension,
                   'devicecurrentlyinused': identifier,
                   'emulator_name': emulator_name
                   }
        template = 'dynamic_analysis/android/dynamic_analyzer.html'

        identifierdevice = itemdata['identifier']
        checksumdevice = itemdata['checksum']
        change_status(queue_display, identifierdevice, checksumdevice, 'AVAILABLE, READY-FOR-ANALYSIS')

        current_live.append(itemdata)   
        analysis_queue.dequeue()

        if api:
            return context
        return render(request, template, context)
    except Exception:
        identifierdevice = itemdata['identifier']
        checksumdevice = itemdata['checksum']
        change_status(queue_display, identifierdevice, checksumdevice, 'ERROR, ANALYSIS-FAILED')
        analysis_queue.dequeue()
        logger.exception('Dynamic Analyzer')
        return print_n_send_error_response(+
            request,
            'Dynamic Analysis Failed.',
            api)