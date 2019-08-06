LEVEL := ./

# Don't try to build any sources on this level
SKIP_LEVEL := 1

# This directory does not contain tasks
IGNORE_DIRS := ./properties/

# The upper limit of the EFFORT, code beyonds which will not be instrumented
THRESHOLD := 0.07
INSTRU_DIR := instrs

# include $(LEVEL)/Makefile.config

%.s: %.i
	$(CC) -S -g -o $@ $^

%.instr.s: %.s
	python3 tracejump.py $^ $@

%.instr: %.instr.o __trace_jump.o ./__VERIFIER.c \
	# @echo $(patsubst %.instr, %.c, $@)
	$(CC) -g -o $(INSTRU_DIR)/$(notdir $@) $^ -no-pie ;\


.PHONY: instr_all, instr_threshold, instr_clean
SOURCE_FILES := $(shell find . -mindepth 2 -name '*.i')
instr_all:
	@python3 -Bc "from makefile_assistant import instrument_all; \
	instrument_all()"
instr_threshold:
	@python3 -Bc "from makefile_assistant import instrument_below_threshold; \
	instrument_below_threshold($(THRESHOLD))"
instr_clean:
	@python3 -Bc "from makefile_assistant import clean_all; \
	clean_all()"
