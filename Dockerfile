FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    build-essential \
    autoconf \
    libtool \
    pkg-config

RUN git clone https://github.com/buffer/libemu.git /opt/libemu \
    && cd /opt/libemu \
    && autoreconf -v -i \
    && ./configure --prefix=/usr \
    && make \
    && make install

ENV LD_LIBRARY_PATH /usr/local/lib

RUN pip3 install git+https://github.com/buffer/pylibemu.git --break-system-packages

WORKDIR /opt/mailoney
COPY . /opt/mailoney

RUN pip3 install -r requirements.txt --break-system-packages

RUN mkdir -p /var/log/mailoney \
    && touch /var/log/mailoney/commands.log \
    && chmod -R 755 /var/log/mailoney

VOLUME /var/log/mailoney

ENTRYPOINT ["/usr/bin/python3", "mailoneyv2.py", "-i", "0.0.0.0", "-p", "25", "-t", "schizo_open_relay", "-logpath", "/var/log/mailoney", "-s", "mailrelay.local", "-D"]
