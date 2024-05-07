import subprocess

def get_available_emulators():
    emulator_command = ["emulator", "-list-avds"]
    process = subprocess.Popen(emulator_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output, _ = process.communicate()
    emulator_names = output.strip().split('\n')[1:]  # Exclude the first line
    return emulator_names

emulator_list = get_available_emulators()
print(emulator_list)
