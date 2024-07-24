import threading
from queue import Queue
import logging
import json
from pathlib import Path

from .dynamic_analyzer import dynamic_analyzer
from .logging_utils import set_avd_name
from EmulatorLauncher import *

logger = logging.getLogger(__name__)

class EmulatorManager:
    def __init__(self):
        self.emulators = {}
        self.lock = threading.Lock()
        self.results = {}
        self.results_dir = Path("dynamic_analysis_results")
        self.results_dir.mkdir(exist_ok=True)
        self.load_persistent_results()
    
    def get_machines(self):
        status = {}
        available_avds = list_avds()
        
        with self.lock:
            for avd_name in available_avds:
                if avd_name in self.emulators:
                    status[avd_name] = {
                        "Running": self.emulators[avd_name]['running']
                    }
                else:
                    status[avd_name] = {
                        "Running": False
                    }
        
        return {"available_avds": status}

    def get_queue_status(self):
        status = {}
        with self.lock:
            for avd_name, emulator in self.emulators.items():
                queue_items = list(emulator['queue'].queue)
                running_task = emulator.get('current_task', None)
                status[avd_name] = {
                    'queue_size': emulator['queue'].qsize() + (1 if running_task else 0),
                    'running': emulator['running'],
                    'current_task': running_task,
                    'queued_tasks': [item[0] for item in queue_items]
                }
        return status

    def load_persistent_results(self):
        for file in self.results_dir.glob("*.json"):
            with open(file, "r") as f:
                task_id = file.stem
                self.results[task_id] = json.load(f)

    def get_or_create_emulator(self, avd_name):
        with self.lock:
            if avd_name not in self.emulators:
                self.emulators[avd_name] = {
                    'queue': Queue(),
                    'running': False,
                    'thread': None,
                    'current_task': None
                }
            return self.emulators[avd_name]

    def save_result(self, task_id, result):
        self.results[task_id] = result
        with open(self.results_dir / f"{task_id}.json", "w") as f:
            json.dump(result, f)

    def queue_scan(self, avd_name, scan_params):
        emulator = self.get_or_create_emulator(avd_name)
        task_id = f"{scan_params['hash']}"
        self.save_result(task_id, None)
        emulator['queue'].put((task_id, scan_params))
        if not emulator['running']:
            result = self.start_emulator_thread(avd_name,scan_params)
        if result == 'failed':
            task_id == 'failed'
        return task_id

    def start_emulator_thread(self, avd_name,scan_params):
        emulator = self.emulators[avd_name]
        emulator['running'] = True
        emulator['thread'] = threading.Thread(target=self.process_emulator_queue, args=(avd_name,))
        emulator['thread'].start()
        while count <= int(scan_params['timeout']):
           time.sleep(1)
           count += 1
           if emulator_name_to_instance(avd_name) not in list_running_emulators():
               time.sleep(4)
               count += 4
               if emulator_name_to_instance(avd_name) not in list_running_emulators():
                   return 'success'
        stop_emulator(emulator_name_to_instance(avd_name))
        return 'failed'

    def process_emulator_queue(self, avd_name):
        set_avd_name(avd_name)
        emulator = self.emulators[avd_name]
        while not emulator['queue'].empty():
            task_id, scan_params = emulator['queue'].get()
            emulator['current_task'] = task_id  # Set current task
            try:
                result = self.run_scan(avd_name, scan_params)
                self.save_result(task_id, result)
            except Exception as e:
                logger.error(f"Scan failed for {avd_name}: {str(e)}")
                self.save_result(task_id, {'error': str(e)})
            finally:
                emulator['queue'].task_done()
                emulator['current_task'] = None  # Clear current task
        emulator['running'] = False
        running_emulators = list_running_emulators()
        for emulator in running_emulators:
            if  get_avd_name(emulator) == avd_name:
                logger.info(f"Stopping emulator: {emulator} for AVD: {avd_name}")
                stop_emulator(emulator)

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
        if task_id not in self.results:
            file_path = self.results_dir / f"{task_id}.json"
            if file_path.exists():
                with open(file_path, "r") as f:
                    return json.load(f)
        return self.results.get(task_id)

# Create a global instance of the EmulatorManager
emulator_manager = EmulatorManager()
