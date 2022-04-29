INSTALL_DIR="/usr/local"
CC=gcc
CFLAGS=-fopenmp -ggdb -Wall -I${INSTALL_DIR}/include
LDFLAGS=-L${INSTALL_DIR}/lib -Wl,-rpath=${INSTALL_DIR}/lib

SRC_poc_openssl := $(wildcard src/poc_openssl/*.c)
OBJ_poc_openssl := $(patsubst %.c, %.o, $(SRC_poc_openssl))
SRC_poc_full_session := $(wildcard src/full_session/*.c)
OBJ_poc_full_session := $(patsubst %.c, %.o, $(SRC_poc_full_session))
SRC_dictionary_reducer := $(wildcard src/dictionary_reducer/*.c)
OBJ_dictionary_reducer := $(patsubst %.c, %.o, $(SRC_dictionary_reducer))


all: poc_openssl poc_full_session dictionary_reducer

poc_openssl: $(OBJ_poc_openssl)
	$(CC) $(CFLAGS) $(OBJ_poc_openssl) -o $@ $(LDFLAGS) -lcrypto

poc_full_session: ${INSTALL_DIR}/lib/libutils.so $(OBJ_poc_full_session)
	$(CC) $(CFLAGS) $(OBJ_poc_full_session) -o $@ $(LDFLAGS) -lcrypto -lutils



dictionary_reducer: ${INSTALL_DIR}/lib/libutils.so $(OBJ_dictionary_reducer)
	$(CC) -fopenmp $(CFLAGS) $(OBJ_dictionary_reducer) -o $@ $(LDFLAGS) -lcrypto -lutils

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

${INSTALL_DIR}/lib/libutils.so:
	$(CC) -c -Wall -Werror -fpic src/utils/utils.c -o src/utils/utils.o  -lcrypto
	$(CC) -shared -o $@ src/utils/utils.o -lcrypto
	cp src/utils/utils.h  ${INSTALL_DIR}/include

clean:
	rm $(OBJ_poc_openssl) $(OBJ_poc_full_session) src/utils/utils.o 

uninstall: clean
	rm poc_openssl ${INSTALL_DIR}/include/utils.h ${INSTALL_DIR}/lib/libutils.so
