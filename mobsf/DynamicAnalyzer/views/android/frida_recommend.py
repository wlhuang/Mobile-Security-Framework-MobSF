import logging
import os

from django.db.models import ObjectDoesNotExist


from mobsf.MobSF.utils import (

    python_list,
    python_dict,

)

from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid


from EmulatorLauncher import *
from mobsf.DynamicAnalyzer.views.android.queue import *
from mobsf.DynamicAnalyzer.views.android.dynamic_analyzer import (
    api_to_script,
    dex_to_script,
    playstore_to_script,
    permisions_to_script,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    send_response,
)
logger = logging.getLogger(__name__)

def frida_recommendations(request,api=False):

    checksum = request.POST['hash']
    data = {}
    selectedscript = []
    try:
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=checksum)
    except:
        data = {'status':'failed',
                'message':'static analysis has not been completed for this hash'}
        return send_response(data, api)


    result = permisions_to_script(static_android_db, selectedscript)
    if result == 'error':
        logger.warning(
            'Failed to get Permissions. '
            'Static Analysis not completed for the app.')
        data = {'status':'failed',
                'message':'Failed to get permissions'}
        return send_response(data, api)
    selectedscript.extend(result)


    result = api_to_script(static_android_db, selectedscript)
    if result == 'error':
        logger.warning(
            'Failed to get Android API. '
            'Static Analysis not completed for the app.')
        data = {'status':'failed',
                'message':'Failed to get Android API'}
        return send_response(data, api)
    selectedscript.extend(result)


    result = dex_to_script(static_android_db, selectedscript)
    if result == 'error':
        logger.warning(
            'Failed to get Dex Files. '
            'Static Analysis not completed for the app.')
        data = {'status':'failed',
                'message':'Failed to get Dex Files'}
        return send_response(data, api)
    selectedscript.extend(result)



    result = playstore_to_script(static_android_db, checksum)
    if result == 'error':
        logger.warning(
        'Failed to get playstore details. '
        'Static Analysis not completed for the app.')
        data = {'status':'failed',
            'message':'Failed to get playstore details'}
        return send_response(data, api)
    selectedscript.extend(result)


    try:
        selectedscript = list(set(selectedscript))
        print('final scripts:', selectedscript)
        textsuggest = []
        for scripts in selectedscript:
            textsuggest.append(scripts)

        data = {
            'status':'ok',
            'recommended scripts':
                textsuggest
            }

        return send_response(data, api)
    except:
        data = {'status':'failed',
                'message':'error within the code'}
        return send_response(data, api)
