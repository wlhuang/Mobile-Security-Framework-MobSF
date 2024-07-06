import threading
import logging

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