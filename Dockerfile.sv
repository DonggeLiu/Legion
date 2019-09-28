FROM ubuntu:bionic

RUN apt-get -y update
RUN apt-get -y upgrade

RUN apt-get -y install git
RUN apt-get -y install wget
RUN apt-get -y install build-essential

RUN apt-get -y install python3 python3-setuptools python3-pip

WORKDIR /root
RUN git clone https://github.com/Alan32Liu/claripy.git
RUN git clone https://github.com/Alan32Liu/angr.git

RUN pip3 install --target lib ./claripy ./angr

