import threading
from queue import Queue
import logging

from EmulatorLauncher import *
from .dynamic_analyzer import dynamic_analyzer

logger = logging.getLogger(__name__)

class EmulatorManager:
    def __init__(self):
        self.emulators = {}
        self.lock = threading.Lock()

    def get_or_create_emulator(self, avd_name):
        with self.lock:
            if avd_name not in self.emulators:
                self.emulators[avd_name] = {
                    'queue': Queue(),
                    'running': False,
                    'thread': None
                }
            return self.emulators[avd_name]

    def queue_scan(self, avd_name, scan_params):
        emulator = self.get_or_create_emulator(avd_name)
        emulator['queue'].put(scan_params)
        if not emulator['running']:
            self.start_emulator_thread(avd_name)

    def start_emulator_thread(self, avd_name):
        emulator = self.emulators[avd_name]
        emulator['running'] = True
        emulator['thread'] = threading.Thread(target=self.process_emulator_queue, args=(avd_name,))
        emulator['thread'].start()

    def process_emulator_queue(self, avd_name):
        emulator = self.emulators[avd_name]
        while not emulator['queue'].empty():
            scan_params = emulator['queue'].get()
            try:
                self.run_scan(avd_name, scan_params)
            except Exception as e:
                logger.error(f"Scan failed for {avd_name}: {str(e)}")
            finally:
                emulator['queue'].task_done()
        emulator['running'] = False

    def run_scan(self, avd_name, scan_params):
        try:
            # Start the emulator if it's not running
            emulator_instance = emulator_name_to_instance(avd_name)
            if emulator_instance not in list_running_emulators():
                print(f"Starting emulator for {avd_name}")  # Debug print
                start_emulator(avd_name)
            else:
                print(f"Emulator {avd_name} is already running")  # Debug print

            # Run the dynamic analyzer
            print(f"Running dynamic analyzer for {avd_name}")  # Debug print
            resp = dynamic_analyzer(scan_params['request'], scan_params['hash'], True, avd_name)

            # Process the result (you can customize this part)
            if 'error' in resp:
                logger.error(f"Scan failed for {avd_name}: {resp['error']}")
            else:
                logger.info(f"Scan completed successfully for {avd_name}")
            return resp
        except Exception as e:
            logger.error(f"Error in run_scan for {avd_name}: {str(e)}")
            return None

# Create a global instance of the EmulatorManager
emulator_manager = EmulatorManager()