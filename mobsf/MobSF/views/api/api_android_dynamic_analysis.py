# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""

from django.views.decorators.csrf import csrf_exempt

from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.DynamicAnalyzer.views.android import (
    dynamic_analyzer,
    operations,
    report,
    tests_common,
    tests_frida,
    frida_recommend,
)
from mobsf.DynamicAnalyzer.views.common import (
    device,
    frida,
)
from EmulatorLauncher import list_avds, list_running_emulators, get_avd_name, start_emulator, stop_emulator

from mobsf.DynamicAnalyzer.views.android.EmulatorManager import emulator_manager

default_timeout_value = 3000

# Dynamic Analyzer APIs
@request_method(['GET'])
@csrf_exempt
def api_get_apps(request):
    """GET - Get Apps for dynamic analysis API."""
    resp = dynamic_analyzer.android_dynamic_analysis(request, True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)

@request_method(['GET'])
@csrf_exempt
def api_queue(request):
    """GET - Get current queue status for all emulators."""
    queue_status = emulator_manager.get_queue_status()
    return make_api_response(queue_status, 200)

@request_method(['GET'])
@csrf_exempt
def api_machines(request):
    """GET - Get current queue status for all emulators."""
    machines = emulator_manager.get_machines()
    return make_api_response(machines, 200)

@request_method(['POST'])
@csrf_exempt
def api_start_analysis(request):
    """POST - Start Dynamic Analysis."""
    avds = list_avds()
    if 'hash' not in request.POST:
        return make_api_response({'error': 'Missing Parameters'}, 422)
    
    hash_value = request.POST['hash']
    avd_name = request.POST.get('avd_name')
    
    if not avd_name:
        return make_api_response({'error': "AVD name must be specified.", 'available_avds': avds}, 422)
    
    if avd_name not in avds:
        return make_api_response({'error': "Invalid AVD name specified.", 'available_avds': avds}, 422)

    if 'timeout' in request.POST:
       timeout = request.POST['timeout']
    else:
       timeout = default_timeout_value
    # Queue the scan for the specified emulator
    scan_params = {
        'request': request,
        'hash': hash_value,
        'timeout': timeout
    }

    if 'cmd' in request.POST:
        scan_params['cmd'] = request.POST['cmd']

    if 'adb_command_action' in request.POST:
            scan_params['adb_command_action'] = request.POST['adb_command_action']

    task_id = emulator_manager.queue_scan(avd_name, scan_params)

    if task_id == 'failed':
        return make_api_response({'message': f'Dynamic analysis has timed out for {avd_name}', 'hash': hash_value}, 500)
    return make_api_response({'message': f'Analysis queued successfully for {avd_name}', 'hash': task_id}, 202)

@request_method(['GET'])
def api_get_analysis_result(request):
    """GET - Get Dynamic Analysis Result."""
    task_id = request.GET.get('hash')
    if not task_id:
        return make_api_response({'error': 'Missing hash parameter'}, 422)

    result = emulator_manager.get_scan_result(task_id)
    if result is None:
        return make_api_response({'message': 'Analysis not found or still in progress'}, 404)
    elif 'error' in result:
        return make_api_response(result, 500)
    else:
        return make_api_response(result, 200)

@request_method(['POST'])
@csrf_exempt
def api_logcat(request):
    """POST - Get Logcat HTTP Streaming API."""
    if 'package' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    lcat = dynamic_analyzer.logcat(request, True)
    if isinstance(lcat, dict):
        if 'error' in lcat:
            return make_api_response(
                lcat, 500)
    return lcat


# Android Operation APIs
@request_method(['POST'])
@csrf_exempt
def api_mobsfy(request):
    """POST - MobSFy API."""
    if 'identifier' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.mobsfy(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_screenshot(request):
    """POST - Screenshot API."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.take_screenshot(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_adb_execute(request):
    """POST - ADB execute API."""
    if 'cmd' not in request.POST or 'deviceidentifier' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.execute_adb(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_root_ca(request):
    """POST - MobSF CA actions API."""
    if 'action' not in request.POST or 'deviceidentifier' not in request.POST:    
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.mobsf_ca(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_global_proxy(request):
    """POST - MobSF Global Proxy API."""
    if 'action' not in request.POST or 'deviceidentifier' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = operations.global_proxy(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


# Android Dynamic Tests APIs
@request_method(['POST'])
@csrf_exempt
def api_act_tester(request):
    """POST - Activity Tester."""
    params = {'test', 'hash', 'deviceidentifier'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_common.activity_tester(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_start_activity(request):
    """POST - Start Activity."""
    params = {'activity', 'hash', 'deviceidentifier'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_common.start_activity(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_tls_tester(request):
    """POST - TLS/SSL Security Tester."""
    params = {'hash', 'deviceidentifier'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_common.tls_tests(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_stop_analysis(request):
    """POST - Stop Dynamic Analysis."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    tests_common.collect_logs(request, True)
    resp = tests_common.download_data(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


# Android Frida APIs
@request_method(['POST'])
@csrf_exempt
def api_frida_recommendations(request):
   """POST - Frida Recommendation"""
   if 'hash' not in request.POST:
       return make_api_response(
           {'error': 'Missing Parameters'}, 422)
   resp = frida_recommend.frida_recommendations(request, True)
   if resp['status'] == 'ok':
       return make_api_response(resp, 200)
   return make_api_response(resp, 500)

@request_method(['POST'])
@csrf_exempt
def api_instrument(request):
    """POST - Frida Instrument."""
    params = {
        'hash',
        'default_hooks',
        'auxiliary_hooks',
        'frida_code'
        'deviceidentifier'
        }
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_frida.instrument(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_api_monitor(request):
    """POST - Frida API Monitor."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_frida.live_api(request, True)
    # live_api can be json or html
    if resp.get('data'):
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_frida_logs(request):
    """POST - Frida Logs."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = frida.frida_logs(request, True)
    # frida logs can be json or html
    if resp.get('data') or resp.get('message'):
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_list_frida_scripts(request):
    """POST - List Frida Scripts."""
    if 'device' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = frida.list_frida_scripts(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_get_script(request):
    """POST - Frida Get Script."""
    if not request.POST.getlist('scripts[]'):
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    if 'device' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = frida.get_script(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


@request_method(['POST'])
@csrf_exempt
def api_get_dependencies(request):
    """POST - Frida Get Runtime Dependencies."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_frida.get_runtime_dependencies(request, True)
    if resp['status'] == 'ok':
        return make_api_response(resp, 200)
    return make_api_response(resp, 500)


# Report APIs
@request_method(['POST'])
@csrf_exempt
def api_dynamic_report(request):
    """POST - Dynamic Analysis report."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = report.view_report(
        request,
        request.POST['hash'],
        True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_dynamic_view_file(request):
    """POST - Dynamic Analysis report."""
    params = {'hash', 'file', 'type'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = device.view_file(request, True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


# acube_json created by xav
@request_method(['POST'])
@csrf_exempt
def api_dynamic_report_acube(request):
    """POST - Dynamic Analysis report."""
    if 'hash' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = report.view_report_acube(
        request,
        request.POST['hash'],
        True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)