CC = gcc
CFLAGS = -O3 -Wall -Wextra
LDFLAGS = -lpcap

.PHONY: all clean

all: dpp_auth_request

dpp_auth_request: dpp_auth_request.c
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f *.o dpp_auth_request
