
from threading import Thread

counter = 0

def up():
    global counter
    for i in range(100000):
        counter+=1

def down():
    global counter
    for i in range(100000):
        counter-=1

t1 = Thread(target=up)
t2 = Thread(target=down)

t1.start()
t2.start()

t1.join()
t2.join()

print(counter)
