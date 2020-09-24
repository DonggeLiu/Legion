FROM ubuntu:20.04

WORKDIR /root
COPY Legion.py Makefile tracejump.py __trace_jump.s __VERIFIER.c __VERIFIER_assume.c __trace_buffered.c  /root/

RUN apt-get update \
    && apt-get install git -y \
    && apt-get install python3 -y \
    && apt-get install python3-pip -y \
    && git clone https://github.com/Alan32Liu/claripy.git \
    && git clone https://github.com/Alan32Liu/angr.git \
    && pip3 install -e /root/claripy \
    && pip3 install -e /root/angr

# RUN mkdir -p /root/sv-benchmarks/c
# COPY sv-benchmarks/c /root/sv-benchmarks/c
