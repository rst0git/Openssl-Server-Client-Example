CC = gcc
CFLAGS += -MMD -MP -Wall -O0 -g3 -ggdb
LDLIBS += -lcrypto -lssl
srcs := $(shell find . -name \*.c)

.PHONY: all
all: apps crt

.PHONY: apps
apps: $(srcs:%.c=%)

.PHONY: crt
crt: server.key server.crt
server.key:
	openssl genrsa -out server.key 4096
server.crt: server.key
	openssl req \
	-new -days 365 -nodes -x509 \
	-subj "/C=/ST=/L=/O=/CN=" \
	-key server.key \
	-out server.crt

.PHONY: clean-all
clean-all: clean clean-crt

clean-crt:
	rm -f server.key server.crt

.PHONY: clean
clean:
	rm -f $(srcs:%.c=%) $(srcs:%.c=%.d)

.PRECIOUS : %.o
%.o : %.c ; $(COMPILE.c) $(OUTPUT_OPTION) $<
% : %.o ; @$(LINK.cpp) $(OUTPUT_OPTION) $^ $(LDLIBS)
