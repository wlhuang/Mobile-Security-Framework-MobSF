"""Shared Frida Views."""
import logging
import glob
import os
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.common.shared import (
    send_response,
)
from mobsf.MobSF.utils import (
    is_file_exists,
    is_md5,
    is_safe_path,
    print_n_send_error_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from EmulatorLauncher import(
    emulator_name_to_instance,
)

logger = logging.getLogger(__name__)


# AJAX


@login_required
@require_http_methods(['POST'])
def list_frida_scripts(request, api=False):
    """List frida scripts from others."""
    scripts = []
    device = request.POST.get('device', 'android')
    if device != 'android':
        device = 'ios'
    others = os.path.join(settings.TOOLS_DIR,
                          'frida_scripts',
                          device,
                          'others')
    files = glob.glob(others + '**/*.js', recursive=True)
    for item in files:
        scripts.append(Path(item).stem)
    scripts.sort()
    return send_response(
        {'status': 'ok',
         'files': scripts},
        api)
# AJAX


@login_required
@require_http_methods(['POST'])
def get_script(request, api=False):
    """Get frida scripts from others."""
    data = {'status': 'ok', 'content': ''}
    try:
        device = request.POST.get('device', 'android')
        if device != 'android':
            device = 'ios'
        scripts = request.POST.getlist('scripts[]')
        others = os.path.join(settings.TOOLS_DIR,
                              'frida_scripts',
                              device,
                              'others')
        script_ct = []
        for script in scripts:
            script_file = os.path.join(others, script + '.js')
            if not is_safe_path(others, script_file):
                data = {
                    'status': 'failed',
                    'message': 'Path traversal detected.'}
                return send_response(data, api)
            if is_file_exists(script_file):
                script_ct.append(Path(script_file).read_text())
        data['content'] = '\n'.join(script_ct)
    except Exception:
        pass
    return send_response(data, api)
# AJAX + HTML


@login_required
def frida_logs(request, api=False):
    try:
        data = {
            'status': 'failed',
            'message': 'Data does not exist.'}
        if api:
            apphash = request.POST['hash']
            #print(apphash)
            stream = True
            deviceidentifier = request.POST.get('deviceidentifier', '')
            #print(deviceidentifier)
        else:
            apphash = request.GET.get('hash', '')
            stream = bool(request.GET.get('stream', ''))
            deviceidentifier = request.GET.get('deviceidentifier', '')
        if not is_md5(apphash):
            data['message'] = 'Invalid hash'
            return send_response(data, api)
        if stream:
            print('hash:', apphash)
            print('deviceidentifier:', deviceidentifier)
            print('stream;', stream)
            apk_dir = os.path.join(settings.UPLD_DIR, apphash + '/')
            frida_logs = os.path.join(apk_dir, '{}_mobsf_frida_out.txt'.format(emulator_name_to_instance(deviceidentifier)))
            print(apk_dir)
            print(frida_logs)
            if not is_file_exists(frida_logs):
                print('does not exists')
                return send_response(data, api)
            with open(frida_logs, 'r',
                      encoding='utf8',
                      errors='ignore') as flip:
                #message = flip.read()
                #print(message)
                data = {
                    'status': 'ok',
                    'message': flip.read(),
                }
                #print(data)
            return send_response(data, api)
        logger.info('Frida Logs live streaming')
        template = 'dynamic_analysis/android/frida_logs.html'
        return render(request,
                      template,
                      {'hash': apphash,
                       'package': request.GET.get('package', ''),
                       'version': settings.MOBSF_VER,
                       'title': 'Live Frida logs'})
    except Exception:
        logger.exception('Frida log streaming')
        err = 'Error in Frida log streaming'
        return print_n_send_error_response(request, err, api)
