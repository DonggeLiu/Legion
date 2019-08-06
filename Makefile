%.s: %.i
	$(CC) -S -g -o $@ $^

%.s: %.c
	$(CC) -S -g -o $@ $^

%.instr.s: %.s
	python3 tracejump.py $^ $@

%.instr: %.instr.o __trace_jump.o __VERIFIER.c
	$(CC) -g -o $@ $^ -no-pie
