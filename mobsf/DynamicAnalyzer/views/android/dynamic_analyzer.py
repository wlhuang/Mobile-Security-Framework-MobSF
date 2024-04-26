# -*- coding: utf_8 -*-
"""Android Dynamic Analysis."""
import logging
import os
import time
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
    'LOCATION': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'],
    'CAMERA': ['CAMERA'],
    'STORAGE': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE'],
}

def map_permissions_to_group(permission):
    parts = permission.split('.')
    permission_name = parts[-1]
    for group, permissions in PERMISSION_GROUPS.items():
        if permission_name in permissions:
            return group
    return None

def cut_string(input_string):
    index = input_string.find('_')
    if index != -1:
        result = input_string[:index]
        return result
    else:
        return input_string

def select_frida_script(permissions):
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
def combine_dicts(*dicts):
    combined_dict = {}
    for d in dicts:
        combined_dict.update(d)
    return combined_dict

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
                'PERMISSIONS': apk.PERMISSIONS
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
    try:
        deviceidentifier = identifier
        #print(identifier)
        activities = None
        exported_activities = None
        text = None
        file_list_without_extension = None
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
            selected_script = select_frida_script(permissions) 
            #print(selected_script)
            text = '// The suggested Frida scripts for dynamic analysis are: '
            for scripts in selected_script:
                text = text + '\n // ' + scripts 
            for scripts in selected_script:
                file_path = 'mobsf/DynamicAnalyzer/tools/frida_scripts/android/others/{}'.format(scripts)
                try:
                    with open(file_path, 'r') as file:
                            texting = file.read()
                            text = text + '\n\n' + texting
                except FileNotFoundError:
                    print("File not found:", file_path)
                except Exception as e:
                    print("Error:", e)
            file_list_without_extension = [filename.replace('.js', '') for filename in selected_script]

        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities. '
                'Static Analysis not completed for the app.')

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
        context = {'package': package,
                   'hash': checksum,
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
        return print_n_send_error_response(
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
