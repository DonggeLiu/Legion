.PHONY: all

all: test.instr test.instr.s test.out.s

# test: test.c
# 	gcc -o $@ $^

%.s: %.c
	$(CC) -S -o $@ $^

%.instr.s: %.s
	python tracejump.py $^ $@

%.instr: %.instr.o __trace_jump.o
	$(CC) -static -o $@ $^

%.out.s: %
	objdump -d $^ > $@
