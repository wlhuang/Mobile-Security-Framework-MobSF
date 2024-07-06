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
        self.results = {}

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
        task_id = f"{scan_params['hash']}"
        self.results[task_id] = None
        emulator['queue'].put((task_id, scan_params))
        if not emulator['running']:
            self.start_emulator_thread(avd_name)
        return task_id

    def start_emulator_thread(self, avd_name):
        emulator = self.emulators[avd_name]
        emulator['running'] = True
        emulator['thread'] = threading.Thread(target=self.process_emulator_queue, args=(avd_name,))
        emulator['thread'].start()

    def process_emulator_queue(self, avd_name):
        emulator = self.emulators[avd_name]
        while not emulator['queue'].empty():
            task_id, scan_params = emulator['queue'].get()
            try:
                result = self.run_scan(avd_name, scan_params)
                self.results[task_id] = result
            except Exception as e:
                logger.error(f"Scan failed for {avd_name}: {str(e)}")
                self.results[task_id] = {'error': str(e)}
            finally:
                emulator['queue'].task_done()
        emulator['running'] = False

    def run_scan(self, avd_name, scan_params):
        try:
            emulator_instance = emulator_name_to_instance(avd_name)
            if emulator_instance not in list_running_emulators():
                start_emulator(avd_name)
            
            resp = dynamic_analyzer(scan_params['request'], scan_params['hash'], True, avd_name)
            return resp
        except Exception as e:
            logger.error(f"Error in run_scan for {avd_name}: {str(e)}")
            return {'error': str(e)}

    def get_scan_result(self, task_id):
        return self.results.get(task_id)

# Create a global instance of the EmulatorManager
emulator_manager = EmulatorManager()