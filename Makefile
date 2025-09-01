CC = gcc
OPENSSL_DIR = /opt/homebrew/opt/openssl@3
CFLAGS = -Wall -Wextra -O2 -g -std=c99 -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR)/lib -lssl -lcrypto -lm

SRCS = fast.c sbox.c prng.c prf.c layers.c cenc_cdec.c
OBJS = $(SRCS:.c=.o)
TEST_SRCS = test_fast.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

TARGET = libfast.a
TEST_TARGET = test_fast
DEBUG_TARGET = debug_test

all: $(TARGET) $(TEST_TARGET)

$(TARGET): $(OBJS)
	ar rcs $@ $^

$(TEST_TARGET): $(TEST_OBJS) $(TARGET)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) $(TARGET) $(LDFLAGS)

%.o: %.c fast.h
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(DEBUG_TARGET): debug_test.c $(TARGET)
	$(CC) $(CFLAGS) -o $@ debug_test.c $(TARGET) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TARGET) $(TEST_TARGET) $(DEBUG_TARGET)

.PHONY: all test clean