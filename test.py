import time

starttime = time.time()
for i in range (1, 10000):
   print(i)
endtime = time.time()
print(endtime - starttime)