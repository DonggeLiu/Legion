import csv
import subprocess as sp
import sys
import time
import traceback

repetition = 100  # trials
SEED = ''.join(sys.argv[1:])


def average(nums):
	return sum(nums)/len(nums)


def variance(nums):
	avg = average(nums)
	return sum([(num-avg)**2 for num in nums])


def print_statics(nums):
	iter_count = []
	time_count = []
	for num in nums:
		iter_count.append(num[0])
		time_count.append(num[1])
	print(
		nums, average(iter_count), variance(iter_count), average(time_count), variance(time_count))


def compute_histogram(command):
	c_list = command.split()
	print(command)
	histogram = []
	for _ in range(repetition):
		ts = time.time()
		history = sp.check_output(c_list)
		te = time.time()
		cost = int(history.splitlines()[-1].split(b',')[0])
		histogram.append((cost, te - ts))
	return histogram


# try:
# 	qs_command = \
# 		"python3 fuzz_qs.py ProgramUnderTest/Instrumented/test_half.instr " + SEED[0]
# 	histogram1 = compute_histogram(qs_command)
# 	print_statics(histogram1)
# except KeyboardInterrupt:
# 	traceback.print_exc(file=sys.stdout)
# 	histogram1 = [0] * repetition

try:
	pc_command = \
		"python3 principes.py ProgramUnderTest/Instrumented/simple_while.instr " + SEED
	histogram2 = compute_histogram(pc_command)
	print_statics(histogram2)
except KeyboardInterrupt:
	traceback.print_exc(file=sys.stdout)
	histogram2 = [0] * repetition

try:
	rd_command = \
		"python3 Benchmarks/pure_random.py ProgramUnderTest/Instrumented/simple_while.instr " + SEED
	histogram3 = compute_histogram(rd_command)
	print_statics(histogram3)
except KeyboardInterrupt:
	traceback.print_exc(file=sys.stdout)
	histogram3 = [0] * repetition


with open(
		'QS_simple_while_100_{}.csv'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())), 'wb') \
		as histogram_file:
	histo_writer = csv.writer(
		histogram_file, delimiter=',')
	histo_writer.writerow(['', 'Current', '', 'Random'])
	for i in range(repetition):
		histo_writer.writerow(
			[i,
			 # histogram1[i][0], histogram1[i][1],
			 histogram2[i][0], histogram2[i][1],
			 histogram3[i][0], histogram3[i][1]])
