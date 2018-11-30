import subprocess as sp
# import tkinter

import csv
import time
import traceback
import sys
import time
from matplotlib.pyplot import plot
from fuzz_qs import run as qs_run
from fuzz_legion import run as lg_run
from pure_random import run as rd_run


REPETITION = 1 # trials
PUT = 'PUT/SourceCode/test_half'
SEED = 's'
QS_TIME = 0.
RD_TIME = 0.

def average(nums):
	return sum(nums)/len(nums)

def variance(nums):
	avg = average(nums)
	return sum([(num-avg)**2 for num in nums])

def print_statics(nums):
	print(nums, average(nums), variance(nums))

def compute_historgram(runner):
	histogram = []
	for _ in range(REPETITION):
		start = time.time()
		history = runner(PUT, SEED)
		end = time.time()
		cost = int(history[-1][0])
		histogram.append([cost, (end-start)])
	return histogram

histogram1, histogram3 = [], []


# try:
# 	histogram1 = compute_historgram(qs_run)
# 	print_statics([num[0] for num in histogram1])
# 	print_statics([num[1] for num in histogram1])
# except:
# 	traceback.print_exc(file=sys.stdout)

# try:
# 	histogram2 = compute_historgram(lg_run)
# 	print_statics(histogram2)
# except:
# 	traceback.print_exc(file=sys.stdout)

try:
	histogram3 = compute_historgram(rd_run)
	print_statics([num[0] for num in histogram3])
	print_statics([num[1] for num in histogram3])
except:
	traceback.print_exc(file=sys.stdout)


with open(
	'tie_breaking_QS_test_half_50_{}.csv'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())), 
	'wb') as histogram_file:
	histo_writer = csv.writer(histogram_file, delimiter = ',', 
		quotechar="|", quoting=csv.QUOTE_MINIMAL)
	histo_writer.writerow(['', 'QS Iter', 'RD Iter', 'QS Time', 'RD Time' ])
	for i in range(REPETITION):
		histo_writer.writerow([i, histogram1[i][0], histogram3[i][0], histogram1[i][1], histogram3[i][1]])

