
%.s: ../SourceCode/%.c
	$(CC) -S -o $@ ../SourceCode/$^

%.instr.s: %.s
	python3 tracejump.py $^ $@

%.instr: %.instr.o __trace_jump.o
	$(CC) -o ../Instrumented/$@ $^ -no-pie
	objdump -d ../Instrumented/$@ > ../Assembly/$@.s
