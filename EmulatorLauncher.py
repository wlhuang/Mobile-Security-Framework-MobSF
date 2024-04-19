import subprocess

def start_emulator(avd_name):
    emulator_command = ["emulator", "-avd", avd_name, "-writable-system", "-no-snapshot"]
    subprocess.Popen(emulator_command)

if __name__ == "__main__":
    avd_name = "Pixel_3a_API_34"
    start_emulator(avd_name)
    avd_name = "Emulator_2"
    start_emulator(avd_name)