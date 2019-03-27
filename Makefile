CC = gcc
CFLAGS += -MMD -MP -Wall -O0 -g3 -ggdb
LDLIBS += -lcrypto -lssl
srcs := $(shell find . -name \*.c)

.PHONY: all
all: apps

.PHONY: apps
apps: $(srcs:%.c=%)

.PHONY: clean-all
clean-all: clean
	rm -f *.pem

.PHONY: clean
clean:
	rm -f $(srcs:%.c=%) $(srcs:%.c=%.d)

.PRECIOUS : %.o
%.o : %.c ; $(COMPILE.c) $(OUTPUT_OPTION) $<
% : %.o ; @$(LINK.cpp) $(OUTPUT_OPTION) $^ $(LDLIBS)
