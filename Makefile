CC=gcc
DBGFLAGS=-g -DDEBUG
CFLAGS=-Wall -std=c99 $(DBGFLAGS)

COMPILE=$(CC) -o $@ $< $(CFLAGS)
NAME=dns

.phony: all $(NAME) clean

all: $(NAME)

$(NAME): $(NAME).c
	$(COMPILE)

clean:
	rm -f $(NAME)