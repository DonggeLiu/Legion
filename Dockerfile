FROM python:3.7

RUN apt-get update
RUN apt-get install apt-utils -y
RUN apt-get install vim -y
RUN apt-get upgrade -y

WORKDIR /root

RUN git clone https://github.com/angr/archinfo.git
RUN git clone https://github.com/angr/pyvex.git
RUN git clone https://github.com/Alan32Liu/claripy.git
RUN git clone https://github.com/angr/cle.git
RUN git clone https://github.com/Alan32Liu/angr.git

COPY Legion.py Makefile tracejump.py __trace_jump.s __VERIFIER.c /root/

RUN pip install -e /root/archinfo
RUN pip install -e /root/pyvex
RUN pip install -e /root/claripy
RUN pip install -e /root/cle
RUN pip install -e /root/angr

# RUN mkdir -p /root/sv-benchmarks/c
# COPY sv-benchmarks/c /root/sv-benchmarks/c
