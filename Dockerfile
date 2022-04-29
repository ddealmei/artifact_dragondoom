FROM ubuntu:20.04

ENV OPENSSL_VERSION="1.1.1l"
ENV RES_DIR="/PoC/shared_folder/results"
ENV DATA_DIR="/PoC/shared_folder/data"
ENV AP_SSID="TestAP"

RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" \
	apt install -y gcc=4:9.3.0-1ubuntu2 make wget vim python3 python3-pip libdwarf-dev macchanger libopenmpi-dev bc
RUN pip3 install statistics

# Install OpenSSL
WORKDIR /tmp
RUN wget -O - -nv "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" 2>/dev/null | tar xz > /dev/null
RUN wget -O - -nv "https://w1.fi/releases/wpa_supplicant-2.9.tar.gz" 2>/dev/null | tar xz > /dev/null

WORKDIR /tmp/openssl-${OPENSSL_VERSION}
RUN ./config no-ssl2 no-tests -g3 -ggdb -gdwarf-4 2>&1 >/dev/null # --debug no-asm no-ssl2 no-tests -g3 -ggdb -gdwarf-4 -fno-inline -O0 -fno-omit-frame-pointer 2>/dev/null 
RUN make -j 2>/dev/null && make -j install_sw 2>&1 >/dev/null

# Install wpa_supplicant linked to local openssl image
RUN DEBIAN_FRONTEND="noninteractive" apt install -y pkg-config libdbus-1-dev libnl-3-dev libnl-genl-3-dev rfkill wireless-tools net-tools
WORKDIR /tmp/wpa_supplicant-2.9/wpa_supplicant
RUN cp defconfig .config && echo "\nCFLAGS += -I/usr/local/include\nLIBS += -L/usr/local/lib\nLIBS_p += -L/usr/local/lib" >> .config 
RUN BINDIR=/usr/local/bin LIBDIR=/usr/local/lib  make -j 
RUN install -v -m755 wpa_cli /usr/local/bin/ 
RUN install -v -m755 wpa_passphrase /usr/local/bin/ 
RUN install -v -m755 wpa_supplicant /usr/local/bin/ 


# Install PoC material (spy, parser, dictionary reducer)
COPY ./PoC_material /tmp/PoC_material/
WORKDIR /tmp/PoC_material/
RUN mkdir -p /PoC
RUN chmod +x spy/FR-trace spy/run_spy.sh
RUN mv spy/FR-trace spy/run_spy.sh  /usr/local/bin/
RUN make && cp poc_openssl poc_full_session dictionary_reducer parser.py attack_simulation* /PoC/
WORKDIR /PoC
