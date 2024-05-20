import subprocess
import os

def snapshot_retrieve(avd_name):
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

def start_emulator(avd_name):
    emulator_command = ["emulator", "-avd", avd_name, "-writable-system", "-snapshot", snapshot_retrieve(avd_name)]
    subprocess.Popen(emulator_command)

# if __name__ == "__main__":
#     avd_name = "Emulator_1"
#     start_emulator(avd_name)
#     avd_name = "Emulator_2"
#     start_emulator(avd_name)
    # avd_name = "Emulator_3"
    # start_emulator(avd_name)
    # avd_name = "Emulator_4"
    # start_emulator(avd_name)
