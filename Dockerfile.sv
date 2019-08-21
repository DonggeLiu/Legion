FROM ubuntu:18.04

RUN apt-get update
RUN apt-get upgrade -y

RUN apt-get install git -y
RUN apt-get install wget -y

RUN apt-get install gcc-multilib -y
RUN apt-get install build-essential -y
RUN apt-get install autoconf -y
RUN apt-get install libtool -y
RUN apt-get install pkg-config -y

RUN apt-get install libbz2-dev -y
RUN apt-get install libffi-dev -y
RUN apt-get install libssl-dev -y

WORKDIR /root

RUN wget https://www.python.org/ftp/python/3.7.4/Python-3.7.4.tgz
RUN tar xf Python-3.7.4.tgz
WORKDIR /root/Python-3.7.4
RUN ./configure
RUN make
RUN make install

RUN git clone https://github.com/Alan32Liu/claripy.git
RUN git clone https://github.com/Alan32Liu/angr.git

