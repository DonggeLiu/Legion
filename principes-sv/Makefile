INSTRU_DIR := ./instrs


%.s: %.i
	$(CC) -S -g -o $@ $^

%.instr.s: %.s
	python3 tracejump.py $^ $@

%.instr: %.instr.o __trace_jump.o ./__VERIFIER.c
	# @echo $(patsubst %.instr, %.c, $@)
	$(CC) -g -o $(INSTRU_DIR)/$(notdir $@) $^ -no-pie ;\
