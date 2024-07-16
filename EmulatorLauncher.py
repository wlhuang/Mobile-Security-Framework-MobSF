import subprocess
import os
import time
from concurrent.futures import ThreadPoolExecutor

def list_avds():
    result = subprocess.run(['emulator', '-list-avds'], stdout=subprocess.PIPE)
    avds = result.stdout.decode('utf-8').strip().split('\n')
    # Filter out lines that do not look like AVD names
    avds = [avd for avd in avds if avd and not avd.startswith('INFO')]
    return avds

def list_running_emulators():
    result = subprocess.run(['adb', 'devices'], stdout=subprocess.PIPE)
    devices = result.stdout.decode('utf-8').splitlines()
    emulators = [line.split()[0] for line in devices if 'emulator' in line]
    return emulators

def get_avd_name(emulator_id):
    result = subprocess.run(['adb', '-s', emulator_id, 'emu', 'avd', 'name'], stdout=subprocess.PIPE, text=True)
    output = result.stdout.splitlines()
    if output:
        avd_name = output[0].strip()
        return avd_name
    return None

def emulator_name_to_instance(emulator):
    emulator_name_list = []
    emulator_instance_list = []
    running_emulators = list_running_emulators()
    print(f"Running emulators: {running_emulators}")  # Debug print
    for i in running_emulators:
        avd_name = get_avd_name(i)
        print(f"AVD name for {i}: {avd_name}")  # Debug print
        if avd_name:
            emulator_instance_list.append(i)
            emulator_name_list.append(avd_name)
    if emulator in emulator_name_list:
        return emulator_instance_list[emulator_name_list.index(emulator)]
    else:
        print(f"Emulator {emulator} not found in running emulators")  # Debug print
        return emulator

def stop_emulator(emulator_id):
    subprocess.run(['adb', '-s', emulator_id, 'emu', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def snapshot_retrieve(avd_name):
    try:
        path = os.path.join("~", ".android/avd/", avd_name, ".avd/snapshots")
        path = os.path.expanduser(path)  # Expand the ~ to the full home directory path
        print(f"Attempting to access path: {path}")  # Debug print
        if not os.path.exists(path):
            print(f"Path does not exist: {path}")  # Debug print
            return None
        
        os.chdir(path)
        
        ls_command = subprocess.Popen(['ls', '-Art'], stdout=subprocess.PIPE)
        grep_command = subprocess.Popen(['grep', 'snap'], stdin=ls_command.stdout, stdout=subprocess.PIPE)

        ls_command.stdout.close()  

        output, _ = grep_command.communicate()
        
        output = output.decode('utf-8').strip()
        
        file_list = output.split('\n')
        
        if not file_list:
            print(f"No snapshot files found in {path}")  # Debug print
            return None
        
        most_recent_file = file_list[-1]
        
        print(f"Most recent snapshot file: {most_recent_file}")  # Debug print
        return most_recent_file
    except Exception as e:
        print(f"Error in snapshot_retrieve: {str(e)}")  # Debug print
        return None

def check_emulator_started(avd_name, attempts=30, delay=2):
    """Check if the emulator has started within the given number of attempts."""
    for i in range(attempts):
        time.sleep(delay)
        if emulator_name_to_instance(avd_name) in list_running_emulators():
            print(f"Emulator {avd_name} started successfully")
            return True
        print(f"Waiting for emulator to start, attempt {i + 1}")
    return False

def start_emulator(avd_name):
    try:
        snapshot = snapshot_retrieve(avd_name)
        if snapshot:
            emulator_command = ["emulator", "-avd", avd_name, "-writable-system", "-snapshot", snapshot]
        else:
            print(f"No snapshot found for {avd_name}, starting without snapshot")
            emulator_command = ["emulator", "-avd", avd_name, "-writable-system", "-no-snapshot"]

        print(f"Starting emulator with command: {' '.join(emulator_command)}")
        subprocess.Popen(emulator_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Using ThreadPoolExecutor to manage the check for the emulator start
        with ThreadPoolExecutor(max_workers=4) as executor:
            future = executor.submit(check_emulator_started, avd_name)
            if future.result():
                print(f"Emulator {avd_name} started successfully")
                return True
            else:
                print(f"Failed to start emulator for AVD: {avd_name}")
                return False

    except Exception as e:
        print(f"Error starting emulator {avd_name}: {str(e)}")
        return False
    
def name_instance(emulator):
    running_emulators = list_running_emulators()
    for i in running_emulators:
        avd_name = get_avd_name(i)
        if avd_name == emulator:
            return i
