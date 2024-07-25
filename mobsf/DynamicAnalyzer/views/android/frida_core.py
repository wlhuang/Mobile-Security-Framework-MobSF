import logging
from pathlib import Path
import sys
import time

from django.conf import settings
import threading
import subprocess
import importlib
from .logging_utils import set_avd_name, get_avd_name

from mobsf.DynamicAnalyzer.views.android.environment import Environment
from mobsf.DynamicAnalyzer.views.android.frida_scripts import (
    class_pattern,
    class_trace,
    get_loaded_classes,
    get_methods,
    string_catch,
    string_compare,
)
from mobsf.MobSF.utils import (
    get_device,
)
from EmulatorLauncher import (
    get_avd_name,
)
logger = logging.getLogger(__name__)
_FPID = None


class Frida:
    lock = threading.Lock()

    def __init__(self, app_hash, package, defaults, auxiliary, others_scripts, extras, code, deviceidentifier):
        self.deviceidentifier = deviceidentifier
        self.hash = app_hash
        self.package = package
        self.defaults = defaults
        self.auxiliary = auxiliary
        self.extras = extras if extras is not None else {}
        self.code = code
        self.frida_dir = Path(settings.TOOLS_DIR) / 'frida_scripts' / 'android'
        self.others_scripts = others_scripts
        self.others_dir = Path(settings.TOOLS_DIR) / 'frida_scripts' / 'android' / 'others'
        self.apk_dir = Path(settings.UPLD_DIR) / self.hash
        self.api_mon = self.apk_dir / 'mobsf_api_monitor.txt'
        self.frida_log = self.apk_dir / '{}_mobsf_frida_out.txt'.format(get_avd_name(deviceidentifier))
        self.deps = self.apk_dir / 'mobsf_app_deps.txt'
        self.clipboard = self.apk_dir / 'mobsf_app_clipboard.txt'
        self.fpid = None
        self.stop_flag = threading.Event()

    def get_scripts(self, script_type, selected_scripts):
        """Get Frida Scripts."""
        combined_script = []
        header = []
        if not selected_scripts:
            return header
        all_scripts = self.frida_dir / script_type
        for script in all_scripts.rglob('*.js'):
            if '*' in selected_scripts:
                combined_script.append(script.read_text('utf-8', 'ignore'))
            if script.stem in selected_scripts:
                header.append(f'send("Loaded Frida Script - {script.stem}");')
                combined_script.append(script.read_text('utf-8', 'ignore'))
        return header + combined_script

    def get_auxiliary(self):
        """Get auxiliary hooks."""
        scripts = []
        if not self.auxiliary:
            return scripts
        for itm in self.auxiliary:
            if itm == 'enum_class':
                scripts.append(get_loaded_classes())
            elif itm == 'get_dependencies':
                scripts.append(get_loaded_classes().replace(
                    '[AUXILIARY] ', '[RUNTIME-DEPS] '))
            elif itm == 'string_catch':
                scripts.append(string_catch())
            elif itm == 'string_compare':
                scripts.append(string_compare())
            elif itm == 'enum_methods' and 'class_name' in self.extras:
                scripts.append(get_methods(self.extras['class_name']))
            elif itm == 'search_class' and 'class_search' in self.extras:
                scripts.append(class_pattern(self.extras['class_search']))
            elif itm == 'trace_class' and 'class_trace' in self.extras:
                scripts.append(class_trace(self.extras['class_trace']))
        return scripts
    
    def get_others_scripts(self):
        """Get specified scripts from the others folder."""
        scripts = []
        for script_name in self.others_scripts:
            script_path = self.others_dir / script_name
            if script_path.exists():
                try:
                    with script_path.open('r', encoding='utf-8') as script_file:
                        script_content = script_file.read()
                    # Remove the .js extension from the script name and content
                    script_name_no_ext = script_name.replace('.js', '')
                    script_content_no_ext = script_content.replace('.js', '')
                    scripts.append(script_content_no_ext)
                    logger.info(f"Loaded script from others folder: {script_name_no_ext}")
                except Exception as e:
                    logger.warning(f"Failed to load script {script_name}: {str(e)}")
            else:
                logger.warning(f"Specified script not found in others folder: {script_name}")
        
        return scripts


    def get_script(self):
        """Get final script."""
        if not self.code:
            self.code = ''
        rpc_list = []
        # Load custom code first
        scripts = [self.code]
        scripts.extend(self.get_scripts('default', self.defaults))
        rpc_list.extend(self.get_scripts('rpc', ['*']))
        scripts.extend(self.get_auxiliary())
        scripts.extend(self.get_scripts('others', self.others_scripts))
        rpc_script = ','.join(rpc_list)
        rpc = f'rpc.exports = {{ \n{rpc_script}\n }};'
        combined = '\n'.join(scripts)
        final = f'{rpc}\n setTimeout(function() {{ \n{combined}\n }}, 1000)'        
        return final

    def frida_response(self, message, data):
        """Function to handle frida responses."""
        if 'payload' in message:
            msg = message['payload']
            api_mon = 'MobSF-API-Monitor: '
            aux = '[AUXILIARY] '
            deps = '[RUNTIME-DEPS] '
            clip = 'mobsf-android-clipboard:'
            if not isinstance(msg, str):
                msg = str(msg)
            if msg.startswith(api_mon):
                self.write_log(self.api_mon, msg.replace(api_mon, ''))
            elif msg.startswith(clip):
                msg = msg.replace(clip, '')
                self.write_log(self.clipboard, f'{msg}\n')
            elif msg.startswith(deps):
                info = msg.replace(deps, '')
                self.write_log(self.deps, f'{info}\n')
                self.write_log(self.frida_log, f'{info}\n')
            elif msg.startswith(aux):
                msg = msg.replace(aux, '[*] ')
                self.write_log(self.frida_log, f'{msg}\n')
            else:
                logger.debug('[Frida] %s', msg)
                self.write_log(self.frida_log, f'{msg}\n')
        else:
            logger.error('[Frida] %s', message)

    def restart_adb_server(self):
        subprocess.run(["adb", "kill-server"])
        subprocess.run(["adb", "start-server"])
    
    def get_connected_devices(self):
        result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lines = result.stdout.strip().split('\n')[1:]  # Skip the first line
        devices = [line.split()[0] for line in lines if 'device' in line]
        return devices

    def check_package(self, device, package_name):
        result = subprocess.run(['adb', '-s', device, 'shell', 'pm', 'list', 'packages'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        packages = result.stdout.strip().split('\n')
        for pkg in packages:
            if package_name in pkg:
                return True
        return False

    def device_package(self, package_name):
        devices = self.get_connected_devices()
        matching_devices = []
        for device in devices:
            if self.check_package(device, package_name):
                matching_devices.append(device)
        return matching_devices[0]
    
    def ensure_emulator_ready(self, deviceid):
        subprocess.run(["adb", "-s", deviceid, "wait-for-device"])
        subprocess.run(["adb", "-s", deviceid, "shell", "getprop", "sys.boot_completed"])

    def spawn(self):
        import frida
        """Frida Spawn."""
        self.restart_adb_server()
        time.sleep(3)
        importlib.reload(frida)
        max_retries = 2
        retry_delay = 5
        for attempt in range(max_retries):
            try:
                set_avd_name(self.deviceidentifier)
                self.deviceidentifier = self.device_package(self.package)
                env = Environment(self.deviceidentifier)
                print("test", self.deviceidentifier)
                self.clean_up()
                self.ensure_frida_server_running(env)

                # Wait for the device to be available
                device = None
                for _ in range(5):
                    try:
                        mgr = None
                        importlib.reload(frida)
                        self.deviceidentifier = self.device_package(self.package)
                        self.ensure_emulator_ready(self.deviceidentifier)
                        print("Attempting to get device:", self.deviceidentifier)
                        mgr = frida.get_device_manager()
                        devices = mgr.enumerate_devices()
                        print("Available devices:", [d.id for d in devices])
                        if mgr.get_device(self.deviceidentifier, timeout=10):
                            device = mgr.get_device(self.deviceidentifier, timeout=10)
                        else:
                            device = mgr.get_usb_device()
                        print("Device obtained:", device)
                        break
                    except frida.InvalidArgumentError as e:
                        print(f"Invalid argument error: {e}")
                        time.sleep(1)
                    except frida.TimedOutError as e:
                        print(f"Timed out: {e}")
                        time.sleep(1)
                    except Exception as e:
                        print(f"Unexpected error: {e}")
                        time.sleep(1)

                if device is None:
                    print("Failed to get device after multiple attempts")

                logger.info('Spawning %s', self.package)
                self.fpid = device.spawn([self.package])
                device.resume(self.fpid)
                time.sleep(3)
                return  # Success, exit the function

            except frida.NotSupportedError:
                logger.exception('Not Supported Error')
            except frida.ServerNotRunningError:
                logger.warning('Frida server is not running')
                continue  # Try again
            except frida.TimedOutError:
                logger.error('Timed out while waiting for device to appear')
            except frida.InvalidArgumentError as e:
                logger.error(f'Invalid argument error: {e}')
            except Exception as e:
                logger.exception('Error Connecting to Frida: %s', e)

            if attempt < max_retries - 1:
                logger.info(f'Retrying in {retry_delay} seconds...')
                time.sleep(retry_delay)
            else:
                logger.error('Max retries reached. Unable to spawn.')

    def ensure_frida_server_running(self, env):
        """Ensure the Frida server is running."""
        try:
            self.stop_frida_sessions()
            env.kill_frida_server()
            time.sleep(2)  # Wait a bit before starting the server again
            env.run_frida_server()
            logger.info("Frida server started successfully")
        except Exception as e:
            logger.exception("Failed to start Frida server: %s", e)

    def stop_frida_sessions(self):
        import frida
        """Stop any existing Frida sessions."""
        try:
            if self.fpid:
                device = frida.get_device(self.deviceidentifier, timeout=5)
                device.kill(self.fpid)
                logger.info("Killed existing Frida session with PID %s", self.fpid)
        except Exception as e:
            logger.exception("Failed to stop existing Frida sessions: %s", e)

    def despawn(self):
        import frida
        """Frida Spawn."""
        try:
            set_avd_name(self.deviceidentifier)
            env = Environment(self.deviceidentifier)
            env.kill_frida_server()
        except frida.NotSupportedError:
            logger.exception('Not Supported Error')
        except Exception as e:
            logger.exception('Error Connecting to Frida: %s', e)
    
    def stop(self):
        self.stop_flag.set()
        env = Environment(self.deviceidentifier)
        env.kill_frida_server()

    def reset_stop_flag(self):
        """Reset the stop flag."""
        self.stop_flag.clear()

    def start_app(self, package_name):
        try:
            subprocess.run(['adb', 'shell', 'monkey', '-p', package_name, '-c', 'android.intent.category.LAUNCHER', '1'], 
                        check=True, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE)
            print(f"Started {package_name}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to start {package_name}: {e}")
            return False
            
    def session(self, pid=None, package=None):
        import frida
        importlib.reload(frida)
        """Use existing session to inject Frida scripts."""
        self.reset_stop_flag()
        while not self.stop_flag.is_set():
            try:
                device = frida.get_device(self.deviceidentifier, settings.FRIDA_TIMEOUT)
                if pid and package:
                    self.fpid = pid
                    self.package = package

                self.start_app(self.package)
                try:
                    front = device.get_frontmost_application()
                    if front and front.pid != self.fpid:
                        logger.warning('Front most app has PID %s', front.pid)
                        self.fpid = front.pid
                    session = device.attach(self.fpid)
                    time.sleep(2)
                    script = session.create_script(self.get_script())
                    script.on('message', self.frida_response)
                    script.load()
                    api = script.exports_sync
                    self.api_handler(api)
                    sys.stdin.read()
                    script.unload()
                    session.detach()
                except Exception as e:
                    logger.exception('Error during session: %s', e)
            except Exception as e:
                logger.exception('Failed to establish a session: %s', e)



    def ps(self):
        import frida
        """Get running process pid."""
        ps_dict = []
        try:
            device = frida.get_device(
                self.deviceidentifier,
                settings.FRIDA_TIMEOUT)
            processes = device.enumerate_applications(scope='minimal')
            if device and processes:
                for process in processes:
                    if process.pid != 0:
                        ps_dict.append({
                            'pid': process.pid,
                            'name': process.name,
                            'identifier': process.identifier,
                        })
        except Exception:
            logger.exception('Failed to enumerate running applications')
        return ps_dict

    def api_handler(self, api):
        """Call Frida rpc functions."""
        loaded_classes = []
        loaded_class_methods = []
        implementations = []
        try:
            raction = self.extras.get('rclass_action')
            rclass = self.extras.get('rclass_name')
            rclass_pattern = self.extras.get('rclass_pattern')
            rmethod = self.extras.get('rmethod_name')
            rmethod_pattern = self.extras.get('rmethod_pattern')
            if raction == 'raction':
                loaded_classes = api.getLoadedClasses()
            elif raction == 'getclasses' and rclass_pattern:
                loaded_classes = api.getLoadedClasses(f'/{rclass_pattern}/i')
            elif raction == 'getmethods' and rclass and rmethod:
                loaded_class_methods = api.getMethods(rclass)
            elif raction == 'getmethods' and rclass and rmethod_pattern:
                loaded_class_methods = api.getMethods(
                    rclass,
                    f'/{rmethod_pattern}/i')
            elif raction == 'getimplementations' and rclass and rmethod:
                implementations = api.getImplementations(rclass, rmethod)
        except Exception:
            logger.exception('Error while calling Frida RPC functions')
        if loaded_classes:
            rpc_classes = self.apk_dir / 'mobsf_rpc_classes.txt'
            loaded_classes = sorted(loaded_classes)
            rpc_classes.write_text('\n'.join(
                loaded_classes), 'utf-8')
        if loaded_class_methods:
            rpc_methods = self.apk_dir / 'mobsf_rpc_methods.txt'
            loaded_class_methods = sorted(loaded_class_methods)
            rpc_methods.write_text('\n'.join(
                loaded_class_methods), 'utf-8')
        if implementations:
            implementations = sorted(implementations)
            rpc_impl = self.apk_dir / 'mobsf_rpc_impl.txt'
            rpc_impl.write_text('\n'.join(
                implementations), 'utf-8')

    def clean_up(self):
        if self.api_mon.exists():
            self.api_mon.unlink()
        if self.frida_log.exists():
            self.frida_log.unlink()
        if self.clipboard.exists():
            self.clipboard.unlink()

    def write_log(self, file_path, data):
        with file_path.open('a',
                            encoding='utf-8',
                            errors='replace') as flip:
            flip.write(data)
