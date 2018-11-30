import subprocess as sp
# import tkinter
from matplotlib.pyplot import plot
import csv


cut_off = 500 # only for csv plotting
repitition = 50 # trials
max_path = 7

command = "python fuzz_new_alternative.py ./test_wide.instr"
c_list = command.split()
# print(c_list)

sum_data = [0] * cut_off
for _ in range(repitition):
	histogram = sp.check_output(c_list + [' '])
	data = [line.split(b',')[1] for line in histogram.splitlines() if line]
	data += [max_path] * (len(sum_data) - len(data))
	for i in range(len(sum_data)):
		sum_data[i] += float(data[i])
	# print(data)
	# print(sum_data)


average_data1 = []
for i in sum_data:
	average_data1.append(i/repitition)

# print(average_data)
# plot(average_data)

command = "python fuzz_new.py ./test_wide.instr"
c_list = command.split()
c_list.append(' ')
# print(c_list)
# print(sp.check_output(c_list + [' ']))

sum_data = [0] * cut_off
for _ in range(repitition):
	# print(c_list)
	histogram = sp.check_output(c_list)
	# print(histogram)
	data = [line.split(b',')[1] for line in histogram.splitlines() if line]
	data += [max_path] * (len(sum_data) - len(data))
	for i in range(len(sum_data)):
		sum_data[i] += float(data[i])
	# print(data)
	# print(sum_data)


average_data2 = []
for i in sum_data:
	average_data2.append(i/repitition)

# print(average_data2)
# plot(average_data)
# 
# average_data = []
# for i in sum_data:
# 	average_data.append(i/10)

# print(average_data)
# # plot(average_data)

command = "python fuzz_random.py ./test_wide.instr"
c_list = command.split()
c_list.append(' ')
# print(c_list)
# print(sp.check_output(c_list + [' ']))

sum_data = [0] * cut_off
for _ in range(repitition):
	# print(c_list)
	histogram = sp.check_output(c_list)
	# print(histogram)
	data = [line.split(b',')[1] for line in histogram.splitlines() if line]
	data += [max_path] * (len(sum_data) - len(data))
	for i in range(len(sum_data)):
		sum_data[i] += float(data[i])
	# print(data)
	# print(sum_data)


average_data3 = []
for i in sum_data:
	average_data3.append(i/repitition)

# print(average_data)
# plot(average_data)


with open('results.csv', 'wb') as csvfile:
	result_writer = csv.writer(csvfile, delimiter = ',', 
		quotechar="|", quoting=csv.QUOTE_MINIMAL)
	result_writer.writerow(['Iteration', 'Equal', 'Different', 'Random'])
	for i in range(len(average_data1)):
		result_writer.writerow(
			[i+1, average_data1[i], average_data2[i], average_data3[i]])














