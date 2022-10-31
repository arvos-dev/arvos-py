FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt -y upgrade && apt install -y linux-headers-5.4.0-124-generic bison build-essential cmake flex git libedit-dev \
  libllvm11 llvm-11-dev libclang-11-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils python3-pip
 
RUN git clone https://github.com/iovisor/bcc.git
RUN mkdir bcc/build
WORKDIR  bcc/build
RUN cmake ..
RUN make
RUN  make install
RUN cmake -DPYTHON_CMD=python3 .. # build python3 binding

WORKDIR /usr/sbin/

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY requirements.txt .

RUN python3 -m pip install -r requirements.txt

COPY arvos_vfs_py.json .
COPY arvos_vfs_py_versions.json .
COPY python_calls.py .

ENV APP_ENV=docker

ENTRYPOINT ["./python_calls.py"]
