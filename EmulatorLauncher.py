import subprocess
import os

def snapshot_retrieve(avd_name):
    try:
        path = "/home/live/.android/avd/"+avd_name+".avd/snapshots"
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
    try:
        emulator_command = ["emulator", "-avd", avd_name, "-writable-system", "-snapshot", snapshot_retrieve(avd_name)]
        subprocess.Popen(emulator_command)
    except:
        emulator_command = ["emulator", "-avd", avd_name, "-writable-system", "-no-snapshot"]
        subprocess.Popen(emulator_command)


