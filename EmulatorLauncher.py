import subprocess
import os
import time

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
        for i in list_running_emulators():
            emulator_instance_list.append(i)
            emulator_name_list.append(get_avd_name(i))
        if emulator in emulator_name_list:
            return emulator_instance_list[emulator_name_list.index(emulator)]
        else:
            return emulator

def stop_emulator(emulator_id):
    subprocess.run(['adb', '-s', emulator_id, 'emu', 'kill'])


def snapshot_retrieve(avd_name):
    try:
        path = os.path.join("~", ".android/avd/",avd_name,".avd/snapshots")
        os.chdir(path)
        
        ls_command = subprocess.Popen(['ls', '-Art'], stdout=subprocess.PIPE)
        grep_command = subprocess.Popen(['grep', 'snap'], stdin=ls_command.stdout, stdout=subprocess.PIPE)

        ls_command.stdout.close()  

        output, _ = grep_command.communicate()

        
        output = output.decode('utf-8').strip()

        
        file_list = output.split('\n')

        
        most_recent_file = file_list[-1]
        
        print(most_recent_file)
        return most_recent_file
    except:
        pass

def start_emulator(avd_name):
    if emulator_name_to_instance(avd_name) in list_running_emulators():
        return  # Emulator is already running

    try:
        snapshot = snapshot_retrieve(avd_name)
        emulator_command = ["emulator", "-avd", avd_name, "-writable-system", "-snapshot", snapshot]
    except:
        emulator_command = ["emulator", "-avd", avd_name, "-writable-system", "-no-snapshot"]
    
    process = subprocess.Popen(emulator_command)
    
    # Wait for the emulator to start
    for _ in range(30):  # 30 attempts, 2 seconds each
        if emulator_name_to_instance(avd_name) in list_running_emulators():
            return
        time.sleep(2)
    
    # If we've reached here, the emulator didn't start
    process.kill()
    raise Exception(f"Failed to start emulator for AVD: {avd_name}")

# Note: We're not implementing a stop_emulator function here because we want to keep the emulators running for subsequent scans


