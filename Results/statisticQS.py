import subprocess as sp
# import tkinter
from matplotlib.pyplot import plot
import csv
import time
import traceback
import sys


repitition = 50 # trials

def average(nums):
	return sum(nums)/len(nums)

def variance(nums):
	avg = average(nums)
	return sum([(num-avg)**2 for num in nums])

def print_statics(nums):
	print(nums, average(nums), variance(nums))

def compute_historgram(command):
	c_list = command.split()

	histogram = []
	for _ in range(repitition):
		history = sp.check_output(c_list + ['s'])
		cost = int(history.splitlines()[-1].split(b',')[0])
		histogram.append(cost)

	return histogram
try:
	command = "python fuzz_qs.py PUT/SourceCode/test_half "
	histogram1 = compute_historgram(command)
	print_statics(histogram1)
except:
	traceback.print_exc(file=sys.stdout)

try:
	command = "python fuzz_legion.py PUT/SourceCode/test_half "
	histogram2 = compute_historgram(command)
	print_statics(histogram2)
except:
	traceback.print_exc(file=sys.stdout)

try:	
	command = "python fuzz_random.py PUT/SourceCode/test_half "
	histogram3 = compute_historgram(command)
	print_statics(histogram3)
except:
	traceback.print_exc(file=sys.stdout)



with open(
	'QS_test_half_50_{}.csv'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())), 
	'wb') as histogram_file:
	histo_writer = csv.writer(histogram_file, delimiter = ',', 
		quotechar="|", quoting=csv.QUOTE_MINIMAL)
	histo_writer.writerow(['', 'QS', 'Prev', 'Random' ])
	for i in range(repitition):
		histo_writer.writerow([i, histogram1[i], histogram2[i], histogram3[i]])

