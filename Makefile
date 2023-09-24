CC=gcc
CFLAGS=-Wall -std=c99 -g

COMPILE=$(CC) -o $@ $< $(CFLAGS)
NAME=dns

.phony: all $(NAME) clean

all: $(NAME)

$(NAME): $(NAME).c
	$(COMPILE)

clean:
	rm -f $(NAME)