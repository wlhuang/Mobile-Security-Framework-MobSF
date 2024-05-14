import threading
import time

class TimedQueue:
    def __init__(self, interval):
        self.__qlist = list()
        self.interval = interval
#        self.__dequeue_thread = threading.Thread(target=self.__dequeue_items)
#        self.__dequeue_thread.daemon = True  # Daemonize the thread to exit with the main program
#        self.__dequeue_thread.start()

    def isEmpty(self):
        return len(self.__qlist) == 0
    
    def __len__(self):
        return len(self.__qlist)

    def enqueue(self, item):
        self.__qlist.append(item)
    
    def dequeue(self):
        assert not self.isEmpty(), "Queue is empty"
        return self.__qlist.pop(0)
    
    # def __dequeue_items(self):
    #     while True:
    #         time.sleep(self.interval)
    #         if not self.isEmpty():
    #             print("Dequeuing:", self.dequeue())
    
    def get_content(self):
        return self.__qlist.copy()
