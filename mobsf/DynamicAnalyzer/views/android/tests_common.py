# -*- coding: utf_8 -*-
"""Available Actions."""
import logging
import os
import re
from .logging_utils import set_avd_name

from django.conf import settings
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    send_response,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.DynamicAnalyzer.views.android.tests_xposed import (
    download_xposed_log,
)
from mobsf.DynamicAnalyzer.views.android.tests_tls import (
    run_tls_tests,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    stop_httptools,
)
from mobsf.MobSF.utils import (
    is_md5,
    python_list,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)
from EmulatorLauncher import (
    list_running_emulators,
    get_avd_name,
    emulator_name_to_instance,
)

logger = logging.getLogger(__name__)


# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def start_activity(request, api=False):
    """Launch a specific activity."""
    try:

        activity = request.POST['activity']
        md5_hash = request.POST['hash']
        emulator = request.POST['deviceidentifier']
    
        emulator_list = []
        for i in list_running_emulators():
            emulator_list.append(get_avd_name(i))
        if emulator in emulator_list:
            env = Environment(identifier=emulator_name_to_instance(emulator)) 
        else:
            data = {'status': 'failed',
                    'message': 'Please use a live emulator',
                    'live emulators':emulator_list}
            return send_response(data, api)
        

        valid_md5 = is_md5(md5_hash)
        valid_act = re.match(r'^[\w]+(\.[\w]+)*$', activity)
        if not valid_act or not valid_md5:
            return invalid_params(api)

        app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        screen_dir = os.path.join(app_dir, 'screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        logger.info('Launching Activity - %s', activity)
        outfile = ('{}act-{}.png'.format(screen_dir, activity))
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=md5_hash)
        package = static_android_db.PACKAGE_NAME
        env.launch_n_capture(package, activity, outfile)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Start Activity')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)


# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def activity_tester(request, api=False):
    """Exported & non exported activity Tester."""
    data = {}
    iden = ''
    try:
        test = request.POST['test']
        emulator = request.POST['deviceidentifier']
        md5_hash = request.POST['hash']

        logger.debug('Received test: %s, emulator: %s, hash: %s', test, emulator, md5_hash)
        set_avd_name(get_avd_name(emulator))
        emulator_list = []
        emulator_list_2 = []
        for i in list_running_emulators():
            emulator_list.append(get_avd_name(i))
            emulator_list_2.append(i)
        
        logger.debug('Running emulators: %s', emulator_list)
        
        if emulator in emulator_list_2:
            env = Environment(emulator)
        else:
            data = {'status': 'failed',
                    'message': 'Please use a live emulator',
                    'live emulators':emulator_list}
            return send_response(data, api)
        
        logger.debug("1001")
        
        if not is_md5(md5_hash):
            return invalid_params(api)
        
        app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        screen_dir = os.path.join(app_dir, 'screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        logger.debug("1001")
        
        static_android_db = StaticAnalyzerAndroid.objects.get(MD5=md5_hash)
        package = static_android_db.PACKAGE_NAME
        logger.debug("1002")
        
        if test == 'exported':
            iden = 'Exported '
            logger.info('Exported activity tester')
            logger.debug("1003")
            activities = python_list(static_android_db.EXPORTED_ACTIVITIES)
            logger.debug("1004")
        else:
            logger.info('Activity tester')
            logger.debug("1005")
            activities = python_list(static_android_db.ACTIVITIES)
            logger.debug("1006")
        
        logger.info('Fetching %sactivities for %s', iden, package)
        if not activities:
            msg = 'No {}Activities found'.format(iden)
            logger.info(msg)
            data = {'status': 'failed',
                    'message': msg}
            return send_response(data, api)
        
        act_no = 0
        logger.info('Starting %sActivity Tester...', iden)
        logger.info('%s %sActivities Identified', str(len(activities)), iden)
        
        for activity in activities:
            act_no += 1
            logger.info('Launching %sActivity - %s. %s', iden, str(act_no), activity)
            if test == 'exported':
                file_iden = 'expact'
            else:
                file_iden = 'act'
            outfile = ('{}{}-{}.png'.format(screen_dir, file_iden, act_no))
            env.launch_n_capture(package, activity, outfile)
        
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('%sActivity tester', iden)
        data = {'status': 'failed', 'message': str(exp)}
        
    return send_response(data, api)


# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def download_data(request, api=False):
    """Download Application Data from Device."""
    logger.info('Downloading app data')
    data = {}
    try:
        env = Environment()
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        package = get_package_name(md5_hash)
        if not package:
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return send_response(data, api)
        apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        stop_httptools(get_http_tools_url(request))
        files_loc = '/data/local/'
        logger.info('Archiving files created by app')
        env.adb_command(['tar', '-cvf', files_loc + package + '.tar',
                         '/data/data/' + package + '/'], True)
        logger.info('Downloading Archive')
        env.adb_command(['pull', files_loc + package + '.tar',
                         apk_dir + package + '.tar'])
        logger.info('Stopping ADB server')
        env.adb_command(['kill-server'])
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Downloading application data')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def collect_logs(request, api=False):
    """Collecting Data and Cleanup."""
    logger.info('Collecting Data and Cleaning Up')
    data = {}
    try:
        env = Environment()
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        package = get_package_name(md5_hash)
        if not package:
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return send_response(data, api)
        apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        lout = os.path.join(apk_dir, 'logcat.txt')
        dout = os.path.join(apk_dir, 'dump.txt')
        logger.info('Downloading logcat logs')
        logcat = env.adb_command(['logcat',
                                  '-d',
                                  package + ':V',
                                  '*:*'])
        with open(lout, 'wb') as flip:
            flip.write(logcat)
        logger.info('Downloading dumpsys logs')
        dumpsys = env.adb_command(['dumpsys'], True)
        with open(dout, 'wb') as flip:
            flip.write(dumpsys)
        if env.get_android_version() < 5:
            download_xposed_log(apk_dir)
        env.adb_command(['am', 'force-stop', package], True)
        logger.info('Stopping app')
        # Unset Global Proxy
        env.unset_global_proxy()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Data Collection & Clean Up failed')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def tls_tests(request, api=False):
    """Perform TLS tests."""
    logger.info('Running TLS/SSL Security tests')
    data = {}
    package = None
    env = None
    try:
        emulator = request.POST['deviceidentifier']
        test_duration = 10
        test_package = 'tls_tests'
        md5_hash = request.POST['hash']
        emulator_list = []
        for i in list_running_emulators():
            emulator_list.append(get_avd_name(i))
        if emulator in emulator_list:
            env = Environment(identifier=emulator_name_to_instance(emulator))
            data = {'status': 'failed',
                    'message': 'Please use a live emulator',
                    'live emulators':emulator_list}
            return send_response(data, api)
    
        if not is_md5(md5_hash):
            return invalid_params(api)
        package = get_package_name(md5_hash)
        if not package:
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return send_response(data, api)
        res = run_tls_tests(
            request,
            md5_hash,
            env,
            package,
            test_package,
            test_duration,
        )
        data = {'status': 'ok', 'tls_tests': res}
    except Exception as exp:
        logger.exception('Checking Application Security in Transit')
        data = {'status': 'failed', 'message': str(exp)}
    finally:
        logger.info('Test Completed. Resuming HTTPS Proxy')
        #env.configure_proxy(package, request)
    return send_response(data, api)
