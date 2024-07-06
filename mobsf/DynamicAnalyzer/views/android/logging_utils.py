import threading
import logging

# Thread-local storage for AVD names
thread_local = threading.local()

class AVDContextFilter(logging.Filter):
    def filter(self, record):
        record.avd_name = getattr(thread_local, 'avd_name', 'Unknown')
        return True

def get_logger(name):
    logger = logging.getLogger(name)
    
    # Remove existing handlers and filters to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    for filter in logger.filters[:]:
        logger.removeFilter(filter)
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(avd_name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.addFilter(AVDContextFilter())
    
    return logger

def set_avd_name(avd_name):
    thread_local.avd_name = avd_name