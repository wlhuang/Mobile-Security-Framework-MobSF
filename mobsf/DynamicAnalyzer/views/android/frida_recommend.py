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

analysis_queue = None
queue_display = []
current_live = [{'identifier': 'TESTINGDATA', 'checksum': 'TESTINGDATA'}]

# Get MOBSF path from ENV
mobsf_path = os.environ.get('MOBSF_PATH') 

# Utilizing path for Frida
directory_path = os.path.join(mobsf_path, 'mobsf/DynamicAnalyzer/tools/frida_scripts/android/others')




#146 Android Permissions Mapped
PERMISSION_GROUPS = {
    'LOCATION': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 
                 'ACCESS_ASSISTED_GPS', 'ACCESS_GPS', 'ACCESS_MEDIA_LOCATION', 'ACCESS_LOCATION_EXTRA_COMMANDS', 
                 'CONTROL_LOCATION_UPDATES', 'INSTALL_LOCATION_PROVIDER', 'ACCESS_MOCK_LOCATION', 
                 'BODY_SENSORS', 'LOCATION', 'GPS'],

    'STORAGE': ['READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE', 'READ_INTERNAL_STORAGE',
                'WRITE_INTERNAL_STORAGE', 'READ_MEDIA_VIDEO', 'READ_MEDIA_IMAGES', 'READ_MEDIA_AUDIO', 
                'ACCESS_ALL_DOWNLOADS', 'ACCESS_CACHE_FILESYSTEM', 'ACCESS_ALL_EXTERNAL_STORAGE',
                'ACCESS_KEYGUARD_SECURE_STORAGE', 'STORAGE_INTERNAL', 'MOUNT_FORMAT_FILESYSTEMS', 'MOUNT_UNMOUNT_FILESYSTEMS',
                'STORAGE'],

    'COMMUNICATION': ['READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS', 'CONTACTS', 'READ_CALL_LOG', 
                      'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS', 'CALL', 'WRITE_VOICEMAIL', 'READ_VOICEMAIL', 
                      'SEND_SMS', 'CALL_PRIVILEGED', 'RECEIVE_SMS', 'SEND_SMS_NO_CONFIRMATION', 'CALL_PHONE'
                      'USE_SIP', 'RECEIVE_MMS', 'BIND_VISUAL_VOICEMAIL_SERVICE', 'ANSWER_PHONE_CALLS',
                      'ADD_VOICEMAIL', 'READ_SMS', 'MANAGE_OWN_CALLS', 'WRITE_SMS', 'SEND_RESPOND_VIA_MESSAGE'],

    'MEDIA' : ['CAMERA', 'RECORD_AUDIO', 'CAPTURE_VIDEO_OUTPUT', 'CAPTURE_SECURE_VIDEO_OUTPUT', 'REMOTE_AUDIO_PLAYBACK', 
               'MODIFY_AUDIO_ROUTING', 'CAPTURE_AUDIO_OUTPUT', 'READ_FRAME_BUFFER'],

    'INTENT' : ['SEND', 'RECEIVE', 'QUERY_ALL_PACKAGES', 'BROADCAST_STICKY', 'INTENT_FILTER_VERIFICATION_AGENT',
                'GET_INTENT_SENDER_INTENT'],

    'NETWORK' : ['ACCESS_WIFI_STATE', 'ACCESS_NETWORK_STATE', 'CHANGE_NETWORK_STATE', 'INTERNET', 'CHANGE_WIFI_MULTICAST_STATE',
                 'CHANGE_WIFI_STATE', 'CONNECTIVITY_INTERNAL', 'READ_NETWORK_USAGE_HISTORY', 
                 'CONTROL_VPN', 'CONNECTIVITY_USE_RESTRICTED_NETWORKS', ' BIND_VPN_SERVICE', 'BIND_TELECOM_CONNECTION_SERVICE', 
                 'MODIFY_NETWORK_ACCOUNTING', 'MANAGE_NETWORK_POLICY', 'CONFIGURE_WIFI_DISPLAY', 'BROADCAST_NETWORK_PRIVILEGED', 
                 'SCORE_NETWORKS'],

    'DEVICEDETAILS': ['READ_PHONE_STATE', 'MODIFY_PHONE_STATE', 'READ_PRIVILEGED_PHONE_STATE', 'LOCAL_MAC_ADDRESS'],

    'BLUETOOTH' : ['BLUETOOTH', 'BLUETOOTH_SCAN', 'BLUETOOTH_CONNECT', 'BLUETOOTH_ADMIN', 'BLUETOOTH_PRIVILEGED', 
                   'PEERS_MAC_ADDRESS', 'RECEIVE_BLUETOOTH_MAP'],

    'CAR' : ['CAR_RADIO', 'CAR_CAMERA', 'CAR_HVAC', 'CAR_MOCK_VEHICLE_HAL', 'CAR_NAVIGATION_MANAGER', 'CAR_PROJECTION', 
             'CONTROL_APP_BLOCKING'],
    
    'BATTERY' : ['DEVICE_POWER', 'BATTERY_STATS'],

    'OTHERS' : ['FLASHLIGHT', 'READ_CALENDAR', 'ACCEPT_HANDOVER', 'REQUEST_INSTALL_PACKAGES', 'USE_FULL_SCREEN_INTENT',
                'POST_NOTIFICATIONS', 'FOREGROUND_SERVICE', 'ACTIVITY_RECOGNITION',
                'WRITE_GSERVICES', 'WRITE_CALENDAR', 'UNINSTALL_SHORTCUT', 'INSTALL_SHORTCUT', 'SET_ALARM', 'USE_BIOMETRIC',
                'SET_WALLPAPER', 'GET_TASKS', 'KILL_BACKGROUND_PROCESSES', 'REORDER_TASKS', 'RECEIVE_BOOT_COMPLETED',
                'DISABLE_KEYGUARD', 'SET_WALLPAPER_HINTS', 'USE_FINGERPRINT', 'TRANSMIT_IR', 'WAKE_LOCK', 'MODIFY_AUDIO_SETTINGS',
                'LOCATION_HARDWARE', 'UPDATE_DEVICE_STATS', 'TETHER_PRIVILEGED', 'VIBRATE', 'INTERACT_ACROSS_USERS_FULL', 
                'INTERACT_ACROSS_USERS', 'UPDATE_APP_OPS_STATS', 'GET_APP_OPS_STATS', 'MANAGE_APP_OPS_RESTRICTIONS', 'PACKET_KEEPALIVE_OFFLOAD',
                'CHANGE_DEVICE_IDLE_TEMP_WHITELIST', 'WRITE_SECURE_SETTINGS', 'MANAGE_DOCUMENTS', 'BIND_WALLPAPER', 'BIND_VR_LISTENER_SERVICE',
                'BIND_TV_INPUT', 'BIND_TEXT_SERVICE', 'BIND_SCREENING_SERVICE']
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

#Playstore Information Keywords Mapped
PLAYSTOREINFORMATION_GROUPS = {
    'MEDIA_screenshot-activity.js': [
        'screenshot', 'screenshots', 'recording screen', 'screen recording',
        'capture screen', 'screen capture', 'screen grab', 'screen shot',
        'screen recorder', 'snapshot', 'screen video', 'record screen activity',
        'screen snapshot', 'screen video recording', 'screen capture tool',
        'screen recorder app'
    ],

    'LOCATION_sensor-monitor.js': [
        'sensor', 'sensors', 'sensor data', 'sensor monitoring', 'sensor tracker',
        'sensor detection', 'motion sensor', 'environmental sensor', 'sensor reading',
        'sensor activity', 'proximity sensor', 'sensor alert', 'sensor status'
    ],

    'MEDIA_media-recorder.js': [
        'media recording', 'audio recording', 'video recording',
        'record media', 'record audio', 'record video', 'media recorder',
        'recording app', 'audio recorder', 'video recorder', 'media capture',
        'capture audio', 'capture video', 'record media activity'
    ],

    'LOCATION_location-accessed.js': [
        'location', 'location access', 'location tracking',
        'GPS', 'location services', 'track location', 'access location',
        'location data', 'geolocation', 'location monitoring', 'location detection',
        'location usage', 'location request', 'location activity', 'location tracker',
        'access GPS', 'GPS tracking', 'location app'
    ],

    'COMMUNICATION_local-data.js': [
    'contacts', 'call logs', 'SMS', 'text messages', 'call history',
    'phone contacts', 'contact list', 'message logs', 'call data',
    'text logs', 'communication data', 'call records', 'message history',
    'contact information', 'contact data', 'call log access', 'message access',
    'phone log', 'SMS records', 'communication history'
    ]
}


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