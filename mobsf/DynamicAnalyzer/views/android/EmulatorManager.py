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
        # Start the emulator if it's not running
        if emulator_name_to_instance(avd_name) not in list_running_emulators():
            start_emulator(avd_name)

        # Run the dynamic analyzer
        resp = dynamic_analyzer(scan_params['request'], scan_params['hash'], True, avd_name)

        # Process the result (you can customize this part)
        if 'error' in resp:
            logger.error(f"Scan failed for {avd_name}: {resp['error']}")
        else:
            logger.info(f"Scan completed successfully for {avd_name}")

# Create a global instance of the EmulatorManager
emulator_manager = EmulatorManager()