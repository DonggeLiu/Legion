.PHONY: clean all

SO = libegion.so
A  = libegion.a

# compiled without -fPIC
O  = __VERIFIER.o __trace_jump.o

# compiled with -fPIC
LO = $(O:.o=.lo)

# for angr
CFLAGS += -no-pie

all: $(SO) $(A) as

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

as:
	ln -s trace-as as
