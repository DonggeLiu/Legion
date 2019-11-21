.PHONY: clean all install

PREFIX = /usr/local

# keep temporary files
# .SECONDARY:

SO = libegion.so
A  = libegion.a

# optimisation
OFLAG ?= -O0

# compiled without -fPIC
O  = __VERIFIER.o __trace_jump.o

# compiled with -fPIC
LO = $(O:.o=.lo)

# for angr
CFLAGS += -no-pie

all: $(SO) $(A) trace/as

clean:
	rm -f $(SO) $(A) $(O) $(LO)
	rm -rf trace/

%.s: %.i
	$(CC) -S -g $(OFLAG) -o $@ $^

%.s: %.c
	$(CC) -S -g $(OFLAG) -o $@ $^

%.instr.s: %.s
	python3 tracejump.py $^ $@

%.instr: %.instr.o __trace_jump.o __VERIFIER.c __VERIFIER_assume.instr.s __trace_buffered.c
	$(CC) -g -o $@ $^ -no-pie

%.instr.obj: %.instr
	objdump -d $^ > $@

$(SO): CFLAGS  += -fPIC
$(SO): LDFLAGS += -shared

%.lo: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.lo: %.s
	$(CC) $(CFLAGS) -c -o $@ $<

$(SO): $(LO)
	$(LD) $(LDFLAGS) -o $@ $^

$(A):  $(O)
	$(AR) $(ARFLAGS) $@ $^

trace:
	mkdir $@

trace/as: trace
	ln trace-as trace/as

install: $(SO) $(A) trace-as trace-cc
	install -m755 -t $(PREFIX)/bin trace-as
	install -m755 -t $(PREFIX)/bin trace-cc
	install -m755 -t $(PREFIX)/lib $(SO)
	install -m644 -t $(PREFIX)/lib $(A)
	mkdir -p $(PREFIX)/bin/trace
	ln -sf $(PREFIX)/bin/trace-as $(PREFIX)/bin/trace/as

uninstall:
	rm $(PREFIX)/bin/trace-as
	rm $(PREFIX)/bin/trace-cc
	rm $(PREFIX)/lib/$(SO)
	rm $(PREFIX)/lib/$(A)
	rm $(PREFIX)/bin/trace/as
	rmdir $(PREFIX)/bin/trace

LOGS = $(wildcard test/results/legion.*.files/*)
ZIPS = $(addsuffix /test-suite.zip,$(LOGS))

.PHONY: zips

%/test-suite.zip: %/Legion
	zip $@ $^ -r

zips: $(ZIPS)
	echo $(ZIPS)

package.zip: legion-sv Legion.py __VERIFIER.c __trace_jump.s tracejump.py benchmark validate legion.xml
	zip -r $@ $^ lib
