FROM ubuntu:bionic
RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get -y update
RUN apt-get -y install python3.6

RUN apt-get -y install python3-setuptools
RUN apt-get -y install wget
RUN apt-get -y install gcc-multilib
RUN apt-get -y install make
RUN apt-get -y install python3.6-dev

RUN wget https://bootstrap.pypa.io/get-pip.py
RUN python3.6 get-pip.py

COPY dep /mnt/dep
WORKDIR /mnt

RUN mkdir lib
RUN pip install dep/claripy dep/angr dep/benchexec --target lib

COPY principes principes-sv.py tracejump.py __trace_jump.s __VERIFIER.c Makefile /mnt/

COPY test.c /mnt/
RUN ./principes test.c
