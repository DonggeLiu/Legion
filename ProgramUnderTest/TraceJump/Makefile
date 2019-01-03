.PHONY: all

all: test.instr test.instr.s test.out.s

# test: test.c
# 	gcc -o $@ $^

%.s: %.c
	$(CC) -S -o $@ $^

%.instr.s: %.s
	python3 tracejump.py $^ $@

%.instr: %.instr.o __trace_jump.o
	$(CC) -o $@ $^ -no-pie

%.out.s: %
	objdump -d $^ > $@
