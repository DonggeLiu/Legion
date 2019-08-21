.PHONY: clean all install

PREFIX = /usr/local

SO = libegion.so
A  = libegion.a

# compiled without -fPIC
O  = __VERIFIER.o __trace_jump.o

# compiled with -fPIC
LO = $(O:.o=.lo)

# for angr
CFLAGS += -no-pie

all: $(SO) $(A) trace/as

clean:
	rm -f $(SO) $(A) $(O) $(LO)

%.s: %.i
	$(CC) -S -g -o $@ $^

%.s: %.c
	$(CC) -S -g -o $@ $^

%.instr.s: %.s
	python3 tracejump.py $^ $@

%.instr: %.instr.o __trace_jump.o __VERIFIER.c
	$(CC) -g -o $@ $^ -no-pie

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



