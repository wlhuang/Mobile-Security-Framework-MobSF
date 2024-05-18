class Queue:
    def __init__(self):
        self.__qlist = list()

    def isEmpty(self):
        return len(self.__qlist) == 0
    
    def __len__(self):
        return len(self.__qlist)

    def enqueue(self, item):
        self.__qlist.append(item)
    
    def dequeue(self):
        if len(self.__qlist) != 0:
            return self.__qlist.pop(0)
        else:
            pass

    def move_to_last(self, item):
        if item in self.__qlist:
            index = self.__qlist.index(item)
            self.__qlist.append(self.__qlist.pop(index))

    def get_content(self):
        return self.__qlist.copy()
