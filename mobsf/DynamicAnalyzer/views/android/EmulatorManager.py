import threading
from queue import Queue
import logging
import json
from pathlib import Path
import requests
from .dynamic_analyzer import dynamic_analyzer
from .logging_utils import set_avd_name
from EmulatorLauncher import *
from mobsf.MobSF.utils import api_key
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

    def get_package_name(self, hash):
        api_url = 'http://127.0.0.1:8000/api/v1/scan'
        headers = {
            'X-Mobsf-Api-Key': api_key(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'hash': hash
        }
        
        try:
            response = requests.post(api_url, headers=headers, data=data)
            response.raise_for_status()
            json_data = response.json()
            return json_data.get('package_name')
        except requests.RequestException as e:
            logger.error(f"Error calling API for hash {hash}: {str(e)}")
            return None
        
    def get_queue_status(self):
        status = {}
        with self.lock:
            for avd_name, emulator in self.emulators.items():
                queue_items = list(emulator['queue'].queue)
                running_task = emulator.get('current_task', None)
                
                queued_tasks = []
                for item in queue_items:
                    hash = item[0]
                    package_name = self.get_package_name(hash)
                    queued_tasks.append({
                        'hash': hash,
                        'package_name': package_name
                    })
                
                current_task_info = None
                if running_task:
                    package_name = self.get_package_name(running_task)
                    current_task_info = {
                        'hash': running_task,
                        'package_name': package_name
                    }
                
                status[avd_name] = {
                    'queue_size': emulator['queue'].qsize() + (1 if running_task else 0),
                    'running': emulator['running'],
                    'current_task': current_task_info,
                    'queued_tasks': queued_tasks
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
                task_id = 'failed'
        return task_id

    def start_emulator_thread(self, avd_name, scan_params):
        emulator = self.emulators[avd_name]
        emulator['running'] = True
        emulator['thread'] = threading.Thread(target=self.process_emulator_queue, args=(avd_name,))
        emulator['thread'].start()

        timeout = int(scan_params['timeout'])
        start_time = time.time()
        
        time.sleep(10)

        while time.time() - start_time < timeout:
            if emulator_name_to_instance(avd_name) in list_running_emulators():
                return 'success'
            time.sleep(5)

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
            else:
                running_emulators = list_running_emulators()
                for emulator in running_emulators:
                    if  get_avd_name(emulator) == avd_name:
                        logger.info(f"Stopping emulator: {emulator} for AVD: {avd_name}")
                        stop_emulator(emulator)
                        start_emulator(avd_name)

            resp = dynamic_analyzer(scan_params['request'], scan_params['hash'], True, avd_name)
            package_name = self.get_package_name(scan_params['hash'])
            resp['package_name'] = package_name
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