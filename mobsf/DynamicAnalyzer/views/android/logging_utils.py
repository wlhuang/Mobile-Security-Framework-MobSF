import threading
import logging
from EmulatorLauncher import *

# Thread-local storage for AVD names
thread_local = threading.local()

class AVDContextFilter(logging.Filter):
    def filter(self, record):
        record.avd_name = getattr(thread_local, 'avd_name', 'Unknown')
        return True

def set_avd_name(avd_name):
    thread_local.avd_name = avd_name

def get_avd_name():
    return thread_local.avd_name

def name_instance(avd_name):
    running_emulators = list_running_emulators()
    for i in running_emulators:
        emulator_name = get_avd_name(i)
        if emulator_name == avd_name:
            return i
        return None

def get_avd_instance():
    instance = name_instance(thread_local.avd_name)
    return instance