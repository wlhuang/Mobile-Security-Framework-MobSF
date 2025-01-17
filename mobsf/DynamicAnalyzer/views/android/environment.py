# -*- coding: utf_8 -*-
"""Dynamic Analyzer Helpers."""
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
from base64 import b64encode
from hashlib import md5
from django.conf import settings

from OpenSSL import crypto

from .logging_utils import *


from frida import __version__ as frida_version

from mobsf.DynamicAnalyzer.tools.webproxy import (
    create_ca,
    get_ca_file,
    get_http_tools_url,
    start_proxy,
    stop_httptools,
)
from mobsf.DynamicAnalyzer.views.android import (
    frida_server_download as fserver,
)
from mobsf.MobSF.utils import (
    get_adb,
    get_device,
    get_proxy_ip,
    is_file_exists,
    python_list,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)
ANDROID_API_SUPPORTED = 34


class Environment:
    def __init__(self, identifier=None):
        self.lock = threading.Lock()
        
        self.identifier = identifier
        
        self.tools_dir = settings.TOOLS_DIR
        self.frida_str = f'MobSF-Frida-{frida_version}'.encode('utf-8')
        self.xposed_str = b'MobSF-Xposed'

        self.identifier2 = get_avd_instance()

    def wait(self, sec):
        """Wait in Seconds."""
        if sec > 0:
            avd_name = get_avd_name()
            logger.info('[%s] Waiting for %s seconds...', avd_name, str(sec))
            time.sleep(sec)

    def check_connect_error(self, output):
        """Check if connect failed."""
        if b'unable to connect' in output or b'failed to connect' in output:
            logger.error('%s', output.decode('utf-8').replace('\n', ''))
            return False
        return True

    def run_subprocess_verify_output(self, cmd, wait=2):
        """Run subprocess and verify execution."""
        out = subprocess.check_output(cmd)  # lgtm [py/command-line-injection]
        self.wait(wait)                        # adb shell is allowed
        return self.check_connect_error(out)

    def connect(self):
        """ADB Connect."""
        self.lock.acquire()
        if not self.identifier2:
            return False
        avd_name = get_avd_name()
        logger.info('[%s] Connecting to Android %s', avd_name, self.identifier2)
        self.run_subprocess_verify_output([get_adb(),
                                           'connect',
                                           self.identifier2])
        self.lock.release()

    def connect_n_mount(self):
        """Test ADB Connection."""
        avd_name = get_avd_name()
        self.lock.acquire()
        if not self.identifier2:
            return False
        
        self.adb_command(['kill-server'])
        self.adb_command(['start-server'], False, True)
        logger.info('ADB Restarted')
        self.wait(2) #test
        logger.info('[%s] Connecting to Android %s', avd_name, self.identifier2)
        if not self.run_subprocess_verify_output([get_adb(),
                                                 'connect',
                                                  self.identifier2]):
            return False
        logger.info('[%s] Restarting ADB Daemon as root', avd_name)
        self.wait(2)
        if not self.run_subprocess_verify_output([get_adb(),
                                                  '-s',
                                                  self.identifier2,
                                                  'root']):
            return False
        logger.info('[%s] Reconnecting to Android Device', avd_name)
        # connect again with root adb
        if not self.run_subprocess_verify_output([get_adb(),
                                                  'connect',
                                                  self.identifier2]):
            return False
        # identify environment
        runtime = self.get_environment()
        logger.info('[%s] Remounting', avd_name)
        # Allow non supported environments also
        self.adb_command(['remount'])
        logger.info('[%s] Performing System check', avd_name)
        self.lock.release()
        if not self.system_check(runtime):
            return False
        return True

    def is_package_installed(self, package, extra):
        """Check if package is installed."""
        success = '\nSuccess' in extra
        out = self.adb_command(['pm', 'list', 'packages'], True)
        pkg = f'{package}'.encode('utf-8')
        pkg_fmts = [pkg + b'\n', pkg + b'\r\n', pkg + b'\r\r\n']
        if any(pkg in out for pkg in pkg_fmts):
            # Windows uses \r\n and \r\r\n
            return True
        if success:
            # Fallback check
            return True
        return False

    def install_apk(self, apk_path, package, reinstall):
        """Install APK and Verify Installation."""
        avd_name = get_avd_name()
        self.lock.acquire()
        if self.is_package_installed(package, '') and reinstall != '0':
            logger.info('[%s] Removing existing installation', avd_name)
            # Remove existing installation'
            self.adb_command(['uninstall', package], False, True)
        # Disable install verification
        self.adb_command([
            'settings',
            'put',
            'global',
            'verifier_verify_adb_installs',
            '0',
        ], True)
        self.wait(5)
        logger.info('[%s] Installing APK - %s', avd_name, package)
        # Install APK
        out = self.adb_command([
            'install',
            '-r',
            '-t',
            '-d',
            '-g',
            apk_path], False, True)
        if not out:
            logger.error('[%s] adb install failed', avd_name)
            return False, 'adb install failed'
        
        # Change battery optimization settings to "Unrestricted"
        logger.info('[%s] Changing battery optimization settings to "Unrestricted" for %s', avd_name, package)
        self.adb_command(['shell', 'cmd', 'deviceidle', 'whitelist', '+{}'.format(package)])

        # Check if the installed APK has BIND_ACCESSIBILITY_SERVICE permission
        accessibility_permission = self.check_accessibility_permission(package)
        if accessibility_permission:
            logger.info('[%s] Accessibility permission found in installed APK', avd_name)
            # Run commands to configure accessibility settings
            logger.info('[%s] Configuring accessibility settings...', avd_name)
            self.execute_accessibility_commands()
        else:
            logger.info('[%s] Accessibility permission not found in installed APK', avd_name)

        self.lock.release()
        # Verify Installation
        return self.is_package_installed(package, out.decode('utf-8', 'ignore')), out.decode('utf-8', 'ignore')

    def check_accessibility_permission(self, package):
        """Check if APK has BIND_ACCESSIBILITY_SERVICE permission."""
        avd_name = get_avd_name()
        try:
            out = self.adb_command(['pm', 'dump', package], True)
            if out is None:
                logger.error('[%s] Error executing adb command to check permissions', avd_name)
                return False
            return b'BIND_ACCESSIBILITY_SERVICE' in out
        except Exception:
            logger.exception('Error checking accessibility permission')
            return False

    def execute_accessibility_commands(self):
        avd_name = get_avd_name()
        """Execute commands to open Accessibility settings and navigate."""
        logger.info('[%s] Opening Accessibility settings', avd_name)
        self.adb_command(['shell', 'am', 'start', '-a', 'android.settings.ACCESSIBILITY_SETTINGS'])
        time.sleep(2)  # Wait for the settings activity to open
        logger.info('[%s] Navigating through Accessibility settings', avd_name)
        # Simulate key events to navigate through the Accessibility settings
        commands = [
            'KEYCODE_TAB',
            'KEYCODE_ENTER',
            'KEYCODE_ENTER',
            'KEYCODE_TAB',
            'KEYCODE_ENTER',
        ]
        for command in commands:
            self.adb_command(['shell', 'input', 'keyevent', command])
            time.sleep(1)  # Add a delay between key events

    def adb_command(self, cmd_list, shell=False, silent=False):
        """ADB Command wrapper."""
        avd_name = get_avd_name()
        args = [get_adb(),
                '-s',
                self.identifier]
        if shell:
            args += ['shell']
        args += cmd_list

        # Log the command being executed
        logger.debug(f"[{avd_name}] Executing ADB command: {' '.join(map(str, args))}")

        # Check for None values in args
        if None in args:
            logger.error(f"[{avd_name}] None value found in ADB command arguments: {args}")
            return None

        try:
            result = subprocess.check_output(
                args,  # lgtm [py/command-line-injection]
                stderr=subprocess.STDOUT)
            return result
        except subprocess.CalledProcessError as e:
            if not silent:
                logger.exception(f'[{avd_name}] Error Running ADB Command: {e.output.decode()}')
            return None
        except Exception as e:
            if not silent:
                logger.exception(f'[{avd_name}] Unexpected error running ADB Command: {str(e)}')
            return None

    def dz_cleanup(self, bin_hash):
        """Clean up before Dynamic Analysis."""
        # Delete ScreenStream Cache
        screen_file = os.path.join(settings.SCREEN_DIR, 'screen.png')
        if os.path.exists(screen_file):
            os.remove(screen_file)
        # Delete Contents of Screenshot Dir
        screen_dir = os.path.join(
            settings.UPLD_DIR, bin_hash + '/screenshots-apk/')
        if os.path.isdir(screen_dir):
            shutil.rmtree(screen_dir)
        else:
            os.makedirs(screen_dir)

    def configure_proxy(self, project, request):
        """HTTPS Proxy."""
        avd_name = get_avd_name()
        self.install_mobsf_ca('install')
        proxy_port = settings.PROXY_PORT
        logger.info('[%s] Starting HTTPS Proxy on %s', avd_name, proxy_port)
        stop_httptools(get_http_tools_url(request))
        start_proxy(proxy_port, project)

    def install_mobsf_ca(self, action):
        """Install or Remove MobSF Root CA."""
        avd_name = get_avd_name()
        mobsf_ca = get_ca_file()
        ca_file = None
        if is_file_exists(mobsf_ca):
            ca_construct = '{}.0'
            pem = open(mobsf_ca, 'rb')
            ca_obj = crypto.load_certificate(crypto.FILETYPE_PEM, pem.read())
            md = md5(ca_obj.get_subject().der()).digest()
            ret = (md[0] | (md[1] << 8) | (md[2] << 16) | md[3] << 24)
            ca_file_hash = hex(ret).lstrip('0x')
            ca_file = os.path.join('/system/etc/security/cacerts/',
                                   ca_construct.format(ca_file_hash))
            pem.close()
        else:
            logger.warning('[%s] mitmproxy root CA is not generated yet.', avd_name)
            return
        if action == 'install':
            avd_name = get_avd_name()
            logger.info('[%s] Installing MobSF RootCA', avd_name)
            self.adb_command(['push',mobsf_ca ,ca_file])
            self.adb_command(['chmod', '644', ca_file], True)
        elif action == 'remove':
            logger.info('[%s] Removing MobSF RootCA', avd_name)
            self.adb_command(['rm',
                              ca_file], True)
        # with a high timeout afterwards

    def set_global_proxy(self, version):
        """Set Global Proxy on device."""
        avd_name = get_avd_name()
        proxy_port = settings.PROXY_PORT
        max_retries = 5
        retry_delay = 2

        with self.lock:  # Use a context manager for the lock
            # Determine proxy IP based on Android version
            if version < 5:
                proxy_ip = get_proxy_ip(self.identifier2)
            else:
                proxy_ip = settings.PROXY_IP

            if not proxy_ip:
                logger.error('[%s] Failed to determine proxy IP', avd_name)
                return False

            # Handle unsupported Android versions
            if version < 4.4:
                logger.warning('[%s] Android version %.1f does not support automatic proxy setting. '
                            'Please set Android VM proxy manually as %s:%s',
                            avd_name, version, proxy_ip, proxy_port)
                return False

            logger.info('[%s] Setting Global Proxy for Android VM', avd_name)
            self.wait(10)

            proxy_setting = f"{proxy_ip}:{proxy_port}"
            command = ['settings', 'put', 'global', 'http_proxy', proxy_setting]

            for attempt in range(max_retries):
                try:
                    self.adb_command(command, shell=True)
                    logger.info('[%s] Successfully set Global Proxy to %s', avd_name, proxy_setting)
                    return True
                except subprocess.CalledProcessError as e:
                    logger.warning('[%s] Attempt %d failed to set Global Proxy: %s',
                                avd_name, attempt + 1, str(e))
                    if attempt < max_retries - 1:
                        logger.info('[%s] Retrying in %d seconds...', avd_name, retry_delay)
                        time.sleep(retry_delay)
                    else:
                        logger.error('[%s] Failed to set Global Proxy after %d attempts',
                                    avd_name, max_retries)
                        return False

        return False

                

    def unset_global_proxy(self):
        """Unset Global Proxy on device."""
        avd_name = get_avd_name()
        logger.info('[%s] Removing Global Proxy for Android VM', avd_name)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'http_proxy'], True)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'global_http_proxy_host'], True)
        self.adb_command(
            ['settings',
             'delete',
             'global',
             'global_http_proxy_port'], True)
        self.adb_command(
            ['settings',
             'put',
             'global',
             'http_proxy',
             ':0'], True)

    def enable_adb_reverse_tcp(self, version):
        """Enable ADB Reverse TCP for Proxy."""
        avd_name = get_avd_name()
        # Androd 5+ supported
        if not version >= 5:
            return
        proxy_port = settings.PROXY_PORT
        logger.info('[%s] Enabling ADB Reverse TCP on %s', avd_name, proxy_port)
        tcp = 'tcp:{}'.format(proxy_port)
        try:
            proc = subprocess.Popen([get_adb(),
                                     '-s', self.identifier2,
                                     'reverse', tcp, tcp],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _, stderr = proc.communicate()
            if b'error: closed' in stderr:
                logger.warning('ADB Reverse TCP works only on'
                               ' Android 5.0 and above. Please '
                               'configure a reachable IP Address'
                               ' in Android proxy settings.')
            elif stderr:
                logger.error(stderr.decode('utf-8').replace('\n', ''))
        except Exception:
            logger.exception('Enabling ADB Reverse TCP')

    def start_clipmon(self):
        """Start Clipboard Monitoring."""
        avd_name = get_avd_name()
        logger.info('[%s] Starting Clipboard Monitor', avd_name)
        args = ['am', 'startservice',
                'opensecurity.clipdump/.ClipDumper']
        self.adb_command(args, True)

    def screen_shot(self, outfile):
        """Take Screenshot."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/screen.png'], True, True)
        self.adb_command(['pull',
                          '/data/local/screen.png',
                          outfile], False, True)

    def screen_stream(self):
        """Screen Stream."""
        self.adb_command(['screencap',
                          '-p',
                          '/data/local/stream.png'],
                         True, True)
        out = self.adb_command(['cat', '/data/local/stream.png'], True, True)
        if out:
            return b64encode(out).decode('utf-8')
        return ''

    def android_component(self, bin_hash, comp):
        """Get APK Components."""
        try:
            anddb = StaticAnalyzerAndroid.objects.get(MD5=bin_hash)
            resp = []
            if comp == 'activities':
                resp = python_list(anddb.ACTIVITIES)
            elif comp == 'receivers':
                resp = python_list(anddb.RECEIVERS)
            elif comp == 'providers':
                resp = python_list(anddb.PROVIDERS)
            elif comp == 'services':
                resp = python_list(anddb.SERVICES)
            elif comp == 'libraries':
                resp = python_list(anddb.LIBRARIES)
            elif comp == 'exported_activities':
                resp = python_list(anddb.EXPORTED_ACTIVITIES)
            return '\n'.join(resp)
        except Exception:
            return 'Static Analysis not done.'

    def get_environment(self):
        """Identify the environment."""
        avd_name = get_avd_name()
        out = self.adb_command(['getprop',
                                'ro.boot.serialno'], True, False)
        out += self.adb_command(['getprop',
                                 'ro.serialno'], True, False)
        out += self.adb_command(['getprop',
                                 'ro.build.user'], True, False)
        out += self.adb_command(['getprop',
                                 'ro.manufacturer.geny-def'],
                                True, False)
        out += self.adb_command(['getprop',
                                 'ro.product.manufacturer.geny-def'],
                                True, False)
        ver = self.adb_command(['getprop',
                                'ro.genymotion.version'],
                               True, False).decode('utf-8', 'ignore')
        if b'EMULATOR' in out:
            logger.info('[%s] Found Android Studio Emulator', avd_name)
            return 'emulator'
        elif (b'genymotion' in out.lower()
                or any(char.isdigit() for char in ver)):
            logger.info('[%s] Found Genymotion x86 Android VM', avd_name)
            return 'genymotion'
        elif b'corellium' in out:
            logger.info('[%s] Found Corellium ARM Android VM', avd_name)
            return 'corellium'
        else:
            logger.warning(
                '[%s] Unable to identify Dynamic Analysis environment. Official support is available only for Android Emulator, Corellium, and Genymotion', avd_name)
            return ''

    def get_android_version(self):
        """Get Android version."""
        out = self.adb_command(['getprop', 'ro.build.version.release'], True, False)
        and_version = out.decode('utf-8').strip()
        
        # Remove any lines that don't look like version numbers
        version_lines = [line for line in and_version.split('\n') if line.replace('.', '').isdigit()]
        
        if not version_lines:
            raise ValueError("Could not find a valid Android version in the output")
        
        and_version = version_lines[-1]  # Take the last line that looks like a version number
        
        if and_version.count('.') > 1:
            and_version = and_version.rsplit('.', 1)[0]
        if and_version.count('.') > 1:
            and_version = and_version.split('.', 1)[0]
        
        try:
            return float(and_version)
        except ValueError:
            raise ValueError(f"Could not convert Android version '{and_version}' to float")

    def get_android_arch(self):
        """Get Android Architecture."""
        out = self.adb_command([
            'getprop',
            'ro.product.cpu.abi'], True)
        return out.decode('utf-8').rstrip()

    def get_android_sdk(self):
        """Get Android API version."""
        out = self.adb_command([
            'getprop',
            'ro.build.version.sdk'], True)
        return out.decode('utf-8').strip()

    def get_device_packages(self):
        """Get all packages from device."""
        device_packages = {}
        out = self.adb_command([
            'pm',
            'list',
            'packages',
            '-f',
            '-3'], True, True)
        if not out:
            return device_packages
        for pkg_str in out.decode('utf-8').rstrip().split():
            path_pkg = pkg_str.split('package:', 1)[1].strip()
            parts = path_pkg.split('.apk=', 1)
            apk = f'{parts[0]}.apk'
            pkg = parts[1]
            if pkg == 'opensecurity.clipdump':
                # Do not include MobSF agent
                continue
            out1 = self.adb_command([
                'md5sum',
                '-b',
                apk], True)
            md5 = out1.decode('utf-8').strip()
            if '.apk' in md5:
                # -b not respected in Android 5.0
                md5 = md5.split()[0]
            device_packages[md5] = (pkg, apk)
        return device_packages

    def get_apk(self, checksum, package):
        """Download APK from device."""
        avd_name = get_avd_name()
        try:
            out_dir = os.path.join(settings.UPLD_DIR, checksum + '/')
            if not os.path.exists(out_dir):
                os.makedirs(out_dir)
            out_file = os.path.join(out_dir, f'{checksum}.apk')
            if is_file_exists(out_file):
                return out_file
            out = self.adb_command([
                'pm',
                'path',
                package], True)
            out = out.decode('utf-8').rstrip()
            path = out.split('package:', 1)[1].strip()
            logger.info('[%s] Downloading APK', avd_name)
            self.adb_command([
                'pull',
                path,
                out_file,
            ])
            if is_file_exists(out_file):
                return out_file
        except Exception:
            return False

    def system_check(self, runtime):
        """Check if /system is writable."""
        avd_name = get_avd_name()
        try:
            try:
                api = self.get_android_sdk()
                if api:
                    logger.info('[%s] Android API Level identified as %s', avd_name, api)
                    if int(api) > ANDROID_API_SUPPORTED:
                        logger.error('[%s] This API Level is not supported for Dynamic Analysis.', avd_name)
                        return False
            except Exception:
                pass
            err_msg = ('VM\'s /system is not writable. '
                       'This VM cannot be used for '
                       'Dynamic Analysis.')
            proc = subprocess.Popen([get_adb(),
                                     '-s', self.identifier2,
                                     'shell',
                                     'touch',
                                     '/system/test'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            _, stderr = proc.communicate()
            if b'Read-only' in stderr:
                logger.error('[%s] %s', avd_name, err_msg)
                if runtime == 'emulator':
                    logger.error('[%s] Please start the AVD as per MobSF documentation!', avd_name)
                return False
        except Exception:
            logger.error('[%s] %s', avd_name, err_msg)
            return False
        return True

    def launch_n_capture(self, package, activity, outfile):
        """Launch and Capture Activity."""
        avd_name = get_avd_name()
        self.adb_command(['am',
                          'start',
                          '-n',
                          package + '/' + activity], True)
        sleep = getattr(settings, 'ACTIVITY_TESTER_SLEEP', 3)
        self.wait(sleep)
        self.screen_shot(outfile)
        logger.info('[%s] Activity screenshot captured', avd_name)

    def run_app(self, package):
        """Launch an app with package name."""
        self.adb_command(['monkey',
                          '-p',
                          package,
                          '-c',
                          'android.intent.category.LAUNCHER',
                          '1'], True)

    def is_mobsfyied(self, android_version):
        """Check is Device is MobSFyed."""
        logger.info('Environment MobSFyed Check')
        if android_version < 5:
            agent_file = '.mobsf-x'
            agent_str = self.xposed_str
        else:
            agent_file = '.mobsf-f'
            agent_str = self.frida_str
        try:
            out = subprocess.check_output(
                [get_adb(),
                 '-s', self.identifier2,
                 'shell',
                 'cat',
                 '/system/' + agent_file])
            if agent_str not in out:
                return False
        except Exception:
            return False
        return True

    def mobsfy_init(self):
        """Init MobSFy."""
        avd_name = get_avd_name()
        version = self.get_android_version()
        logger.info('[%s] Android Version identified as %s', avd_name, version)
        try:
            if version < 5:
                self.xposed_setup(version)
                self.mobsf_agents_setup('xposed')
            else:
                self.frida_setup()
                self.mobsf_agents_setup('frida')
            logger.info('[%s] MobSFying Completed!', avd_name)
            return version
        except Exception:
            logger.exception('[%s] Failed to MobSFy Android Instance', avd_name)
            return False

    def mobsf_agents_setup(self, agent):
        """Setup MobSF agents."""
        create_ca()
        # Install MITM RootCA
        self.install_mobsf_ca('install')
        if agent == 'frida':
            agent_file = '.mobsf-f'
            agent_str = self.frida_str
        else:
            agent_file = '.mobsf-x'
            agent_str = self.xposed_str
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(agent_str)
        f.close()
        self.adb_command(['push', f.name, '/system/' + agent_file])
        os.unlink(f.name)

    def xposed_setup(self, android_version):
        """Setup Xposed."""
        xposed_dir = 'onDevice/xposed/'
        xposed_modules = xposed_dir + 'modules/'
        # Install MobSF Agents for Xposed
        clip_dump_apk = os.path.join(self.tools_dir,
                                     xposed_dir,
                                     'ClipDump.apk')
        logger.info('Installing MobSF Clipboard Dumper')
        self.adb_command(['install', '-r', clip_dump_apk])
        if android_version < 5:
            logger.info('Installing Xposed for Kitkat and below')
            xposed_apk = os.path.join(self.tools_dir,
                                      xposed_dir,
                                      'Xposed.apk')
            hooks = os.path.join(self.tools_dir,
                                 xposed_modules,
                                 'hooks.json')
            droidmon = os.path.join(self.tools_dir,
                                    xposed_modules,
                                    'Droidmon.apk')
            logger.info('Installing Droidmon API Analyzer')
            self.adb_command(['install', '-r', droidmon])
            logger.info('Copying Droidmon hooks config')
            self.adb_command(['push', hooks, '/data/local/tmp/'])
        else:
            logger.info('Installing Xposed for Lollipop and above')
            xposed_apk = os.path.join(self.tools_dir,
                                      xposed_dir,
                                      'XposedInstaller_3.1.5.apk')
        self.adb_command(['install', '-r', xposed_apk])
        # Xposed Modules and Support Files
        justrustme = os.path.join(self.tools_dir,
                                  xposed_modules,
                                  'JustTrustMe.apk')
        rootcloak = os.path.join(self.tools_dir,
                                 xposed_modules,
                                 'com.devadvance.rootcloak2_v18_c43b61.apk')
        proxyon = os.path.join(self.tools_dir,
                               xposed_modules,
                               'mobi.acpm.proxyon_v1_419b04.apk')
        sslunpin = os.path.join(self.tools_dir,
                                xposed_modules,
                                'mobi.acpm.sslunpinning_v2_37f44f.apk')
        bluepill = os.path.join(self.tools_dir,
                                xposed_modules,
                                'AndroidBluePill.apk')
        logger.info('Installing JustTrustMe')
        self.adb_command(['install', '-r', justrustme])
        logger.info('Installing SSLUnpinning')
        self.adb_command(['install', '-r', sslunpin])
        logger.info('Installing ProxyOn')
        self.adb_command(['install', '-r', proxyon])
        logger.info('Installing RootCloak')
        self.adb_command(['install', '-r', rootcloak])
        logger.info('Installing Android BluePill')
        self.adb_command(['install', '-r', bluepill])
        logger.info('[%s] Launching Xposed Framework.')
        xposed_installer = ('de.robv.android.xposed.installer/'
                            'de.robv.android.xposed.installer.'
                            'WelcomeActivity')
        self.adb_command(['am', 'start', '-n',
                          xposed_installer], True)

    def frida_setup(self):
        """Setup Frida."""
        frida_arch = None
        arch = self.get_android_arch()
        logger.info('Android OS architecture identified as %s', arch)
        if arch in ['armeabi-v7a', 'armeabi']:
            frida_arch = 'arm'
        elif arch == 'arm64-v8a':
            frida_arch = 'arm64'
        elif arch == 'x86':
            frida_arch = 'x86'
        elif arch == 'x86_64':
            frida_arch = 'x86_64'
        else:
            logger.error('Make sure a Genymotion Android x86 VM'
                         ' or Android Studio Emulator'
                         ' instance is running')
            return
        frida_bin = f'frida-server-{frida_version}-android-{frida_arch}'
        stat = fserver.update_frida_server(frida_arch, frida_version)
        if not stat:
            msg = ('Cannot download frida-server binary. You will need'
                   f' {frida_bin} in {settings.DWD_DIR} for '
                   'Dynamic Analysis to work')
            logger.error('%s', msg)
            return
        frida_path = os.path.join(settings.DWD_DIR, frida_bin)
        logger.info('Copying frida server for %s', frida_arch)
        self.adb_command(['push', frida_path, '/system/fd_server'])
        self.adb_command(['chmod', '755', '/system/fd_server'], True)

    def run_frida_server(self):
        """Start Frida Server."""
        check = self.adb_command(['ps'], True)
        if b'fd_server' in check:
            logger.info('Frida Server is already running')
            return

        def start_frida():
            fnull = open(os.devnull, 'w')
            argz = [get_adb(),
                    '-s',
                    self.identifier,
                    'shell',
                    '/system/fd_server']
            subprocess.call(argz, stdout=fnull, stderr=subprocess.STDOUT)
        trd = threading.Thread(target=start_frida)
        trd.daemon = True
        trd.start()
        logger.info(' Starting Frida Server')
        logger.info('Waiting for 2 seconds...')
        time.sleep(2)


    def kill_frida_server(self):
        """Kill Frida Server."""
        check = self.adb_command(['ps'], True)
        if b'fd_server' not in check:
            logger.info('Frida Server is not running')
            return
        
        def stop_frida():
            fnull = open(os.devnull, 'w')
            argz = [get_adb(),
                    '-s',
                    self.identifier,
                    'shell',
                    'pkill -f fd_server']
            subprocess.call(argz, stdout=fnull, stderr=subprocess.STDOUT)
        
        trd = threading.Thread(target=stop_frida)
        trd.daemon = True
        trd.start()
        logger.info('Stopping Frida Server')
        logger.info('Waiting for 2 seconds...')
        time.sleep(2)