# -*- coding: utf_8 -*-

#work done on part 2b
"""Android Dynamic Analysis."""
import logging
import os
import time
import subprocess
from pathlib import Path
from json import dump

from shelljob import proc


from django.http import (HttpResponseRedirect,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render
from django.db.models import ObjectDoesNotExist

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
    strict_package_check,
)
from mobsf.MobSF.views.scanning import add_to_recent_scan
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)

PERMISSION_GROUPS = {
    'LOCATION': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 
                 'ACCESS_ASSISTED_GPS', 'ACCESS_GPS', 'ACCESS_MEDIA_LOCATION', 'ACCESS_LOCATION_EXTRA_COMMANDS', 
                 'CONTROL_LOCATION_UPDATES', 'INSTALL_LOCATION_PROVIDER', 'LOCATION', 'GPS'],

    'STORAGE': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE', 'READ_INTERNAL_STORAGE',
                'WRITE_INTERNAL_STORAGE', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_IMAGES', 'READ_MEDIA_AUDIO', 
                'STORAGE'],

    'COMMUNICATION': ['READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS', 'CONTACTS', 'READ_CALL_LOG', 
                      'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS', 'CALL', 'WRITE_VOICEMAIL', 'READ_VOICEMAIL', 
                      'SEND_SMS', 'CALL_PRIVILEGED', 'RECEIVE_SMS', 'SEND_SMS_NO_CONFIRMATION', 'CALL_PHONE'
                      'USE_SIP', 'RECEIVE_MMS', 'BIND_VISUAL_VOICEMAIL_SERVICE'],

    'MEDIA' : ['CAMERA', 'RECORD_AUDIO'],

    'INTENT' : ['SEND', 'RECEIVE', 'QUERY_ALL_PACKAGES', 'BROADCAST_STICKY'],

    'NETWORK' : ['ACCESS_WIFI_STATE', 'ACCESS_NETWORK_STATE', 'CHANGE_NETWORK_STATE', 'INTERNET', 'CHANGE_WIFI_MULTICAST_STATE'
                 'CHANGE_WIFI_STATE', 'CHANGE_WIFI_MULTICAST_STATE', 'CONNECTIVITY_INTERNAL', 'READ_NETWORK_USAGE_HISTORY', 'CONTROL_VPN',
                 'CONNECTIVITY_USE_RESTRICTED_NETWORKS', ' BIND_VPN_SERVICE', 'BIND_TELECOM_CONNECTION_SERVICE', 
                ],

    'DEVICEDETAILS': ['READ_PHONE_STATE', 'MODIFY_PHONE_STATE', 'READ_PRIVILEGED_PHONE_STATE', 'LOCAL_MAC_ADDRESS'],

    'BLUETOOTH' : ['BLUETOOTH', 'BLUETOOTH_SCAN', 'BLUETOOTH_CONNECT', 'BLUETOOTH_ADMIN', 'BLUETOOTH_PRIVILEGED', 
                   'PEERS_MAC_ADDRESS'],

    'CAR' : ['CAR_RADIO', 'CAR_CAMERA', 'CAR_HVAC', 'CAR_MOCK_VEHICLE_HAL', 'CAR_NAVIGATION_MANAGER', 'CAR_PROJECTION', 
             'CONTROL_APP_BLOCKING'],
    
    'BATTERY' : ['DEVICE_POWER'],

    'OTHERS' : ['FLASHLIGHT', 'READ_CALENDAR', 'ACCEPT_HANDOVER', 'REQUEST_INSTALL_PACKAGES', 'USE_FULL_SCREEN_INTENT',
                'POST_NOTIFICATIONS', 'FOREGROUND_SERVICE', 'ACTIVITY_RECOGNITION',
                'WRITE_GSERVICES', 'WRITE_CALENDAR', 'UNINSTALL_SHORTCUT', 'INSTALL_SHORTCUT', 'SET_ALARM', 'USE_BIOMETRIC',
                'SET_WALLPAPER', 'GET_TASKS', 'KILL_BACKGROUND_PROCESSES', 'REORDER_TASKS', 'RECEIVE_BOOT_COMPLETED',
                'DISABLE_KEYGUARD', 'SET_WALLPAPER_HINTS', 'USE_FINGERPRINT', 'TRANSMIT_IR', 'WAKE_LOCK', 'MODIFY_AUDIO_SETTINGS',
                'LOCATION_HARDWARE', 'UPDATE_DEVICE_STATS', 'TETHER_PRIVILEGED', 'VIBRATE', 'INTERACT_ACROSS_USERS_FULL', 
                'INTERACT_ACROSS_USERS', 'UPDATE_APP_OPS_STATS', 'GET_APP_OPS_STATS', 'MANAGE_APP_OPS_RESTRICTIONS', 'PACKET_KEEPALIVE_OFFLOAD',
                'CHANGE_DEVICE_IDLE_TEMP_WHITELIST', 'WRITE_SECURE_SETTINGS', 'MANAGE_DOCUMENTS', 'BIND_WALLPAPER', 'BIND_VR_LISTENER_SERVICE',
                'BIND_TV_INPUT', 'BIND_TEXT_SERVICE', 'BIND_SCREENING_SERVICE', ''
                ]
}

# 54 Android APIs Mapped
API_GROUPS = {
    'DEX': ['api_dexloading', 'api_dex_manipulate'],

    'CRYPTOGRAPHY': ['api_crypto', 'api_base64_encode', 'api_message_digest', 'api_base64_decode', 'api_keystore'],

    'STORAGE': ['api_local_file_io'],

    'INTENT': ['api_ipc', 'api_start_activity', 'api_send_broadcast', 'api_start_service', 'api_installed'],

    'COMMUNICATION': ['api_sms_call'],

    'LOCATION': ['api_get_location', 'api_gps'],

    'HIDDENAPP': ['api_hide_app_icon'],

    'DEVICEDETAILS': ['api_get_advertising', 'api_get_network', 'api_get_wifi', 'api_get_cell',
                      'api_get_subscriber', 'api_get_device', 'api_get_soft', 'api_get_sim_serial',
                      'api_get_sim_provider', 'api_get_sim_operator', 'api_get_phone',
                      'api_get_running_app_processes', 'api_get_system_service'],

    'NETWORK': ['api_jar_url', 'api_https_connection', 'api_url', 'api_webview_post', 'api_webview_get',
                'api_http_connection', 'api_web', 'api_tcp', 'api_tcp_server', 'api_udp_datagram_socket',
                'api_udp_datagram'],

    'OTHERS': ['api_native_code', 'api_passkeys', 'api_certificate_handling', 'api_javascript_interface_methods',
               'api_clipboard', 'api_notifications', 'api_os_command', 'api_java_reflection', 'api_content_provider',
               'api_kill_process', 'api_obfuscation', 'api_webview']
}

# PLAYSTOREINFORMATION_GROUPS = {
#     'screenshot-activity.js': ['screenshot', 'screenshots', 'recording screen', 'screen recording'],
#     'sensor-monitoring.js': ['sensor', 'sensors',.........],
#     'media-recorder.js': ['']
# }

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

# Permission Groups
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
        #print(group)
        if group:
            for filename in os.listdir('mobsf/DynamicAnalyzer/tools/frida_scripts/android/others'):
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
        #print(group)
        if group:
            for filename in os.listdir('mobsf/DynamicAnalyzer/tools/frida_scripts/android/others'):
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
                    'version': settings.MOBSF_VER,
                    }
        #print(context)
        if api:
            return context
        template = 'dynamic_analysis/android/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis')
        return print_n_send_error_response(request, exp, api)


def dynamic_analyzer(request, checksum, identifier, api=False):
    """Android Dynamic Analyzer Environment."""
    apiKey = api_key()
    try:
        deviceidentifier = identifier
        #print(identifier)
        activities = None
        exported_activities = None
        textsuggest = ' // The suggested Frida scripts for dynamic analysis are: '
        textscripts = ' '
        file_list_without_extension = []
        selected_script = []
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
            #print(permissionlist)
            selectedscript = select_frida_script_permissions(permissions)
            if len(selected_script) == 0:
                selected_script = selectedscript
            else:
                selected_script = selected_script + selectedscript
            #print(selected_script)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')
            
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            androidapis = eval(static_android_db.ANDROID_API)
            keys = androidapis.keys()
            keys_list = list(keys)
            selectedscript = select_frida_script_androidapis(keys_list)
            if len(selected_script) == 0:
                selected_script = selectedscript
            else:
                selected_script = selected_script + selectedscript
            print(selected_script)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')
            
        try:
            dex = static_android_db.APKID
            if len(dex) > 0:
                if 'DEX_dex.js' not in selected_script:
                    selected_script.append('DEX_dex.js')
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')
        except:
            pass
        
        try: 
            selected_script = list(set(selected_script))
            #print(selected_script)
            for scripts in selected_script:
                textsuggest = textsuggest + '\n // ' + scripts 

            for scripts in selected_script:
                file_path = 'mobsf/DynamicAnalyzer/tools/frida_scripts/android/others/{}'.format(scripts)
                try:
                    with open(file_path, 'r') as file:
                            texting = file.read()
                            textscripts = textscripts + '\n\n' + texting
                except FileNotFoundError:
                    print("File not found:", file_path)
                except Exception as e:
                    print("Error:", e)
                file_list_without_extension = [filename.replace('.js', '') for filename in selected_script]

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
                   'devicecurrentlyinused': identifier}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        if api:
            return context
        return render(request, template, context)
    except Exception:
        logger.exception('Dynamic Analyzer')
        return print_n_send_error_response(+
            request,
            'Dynamic Analysis Failed.',
            api)


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

        context = {'apps': scan_apps,
                    'title': 'MobSF Dynamic Analysis',
                    'version': settings.MOBSF_VER,
                    'emulator_list': emulator_list
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
    print(checksum)
    print(identifier)
    #apiKey = api_key()
    try:
        deviceidentifier = identifier
        #print(identifier)
        activities = None
        exported_activities = None
        textsuggest = ' // The suggested Frida scripts for dynamic analysis are: '
        textscripts = ' '
        file_list_without_extension = []
        selected_script = []
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
            #print(permissionlist)
            selectedscript = select_frida_script_permissions(permissions)
            if len(selected_script) == 0:
                selected_script = selectedscript
            else:
                selected_script = selected_script + selectedscript
            #print(selected_script)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')
            
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            androidapis = eval(static_android_db.ANDROID_API)
            keys = androidapis.keys()
            keys_list = list(keys)
            selectedscript = select_frida_script_androidapis(keys_list)
            if len(selected_script) == 0:
                selected_script = selectedscript
            else:
                selected_script = selected_script + selectedscript
            print(selected_script)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')
            
        try:
            dex = static_android_db.APKID
            if len(dex) > 0:
                if 'DEX_dex.js' not in selected_script:
                    selected_script.append('DEX_dex.js')
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')
        except:
            pass
        
        try: 
            selected_script = list(set(selected_script))
            #print(selected_script)
            for scripts in selected_script:
                textsuggest = textsuggest + '\n // ' + scripts 

            for scripts in selected_script:
                file_path = 'mobsf/DynamicAnalyzer/tools/frida_scripts/android/others/{}'.format(scripts)
                try:
                    with open(file_path, 'r') as file:
                            texting = file.read()
                            textscripts = textscripts + '\n\n' + texting
                except FileNotFoundError:
                    print("File not found:", file_path)
                except Exception as e:
                    print("Error:", e)
                file_list_without_extension = [filename.replace('.js', '') for filename in selected_script]

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
                   'devicecurrentlyinused': identifier}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        if api:
            return context
        return render(request, template, context)
    except Exception:
        logger.exception('Dynamic Analyzer')
        return print_n_send_error_response(+
            request,
            'Dynamic Analysis Failed.',
            api)