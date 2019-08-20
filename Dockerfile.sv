FROM ubuntu:18.04

RUN apt-get update
RUN apt-get upgrade -y

RUN apt-get install python3 -y
RUN apt-get install python3-dev -y
RUN apt-get install python3-distutils python3-setuptools -y

RUN apt-get install git -y
RUN apt-get install wget -y

RUN apt-get install gcc-multilib -y
RUN apt-get install build-essential -y
RUN apt-get install autoconf -y
RUN apt-get install libtool -y
RUN apt-get install pkg-config -y

WORKDIR /root

RUN wget https://bootstrap.pypa.io/get-pip.py
RUN python3.6 get-pip.py

RUN git clone https://github.com/Alan32Liu/claripy.git
RUN git clone https://github.com/Alan32Liu/angr.git

RUN pip install virtualenv
RUN virtualenv -p python3.6 python3.6

RUN apt-get install python3.7 -y
RUN apt-get install python3.7-dev -y
RUN virtualenv -p python3.7 python3.7

# RUN pip install --target lib 2to3 3to2 /root/claripy /root/angr
