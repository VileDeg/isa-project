CC=gcc
DBGFLAGS=-g -DDEBUG
CFLAGS=-Wall -std=c99 $(DBGFLAGS)

NAME=dns

SRCS=$(NAME).c args.c
OBJS:=$(SRCS:c=o)

HDRS=args.h

.phony: all $(NAME) clean

all: $(NAME)

$(NAME): $(OBJS) Makefile
	$(CC) -o $@ $(OBJS)

$(OBJS): %.o: %.c Makefile
	$(CC) -c $< $(CFLAGS)

clean:
	rm -f $(NAME) $(OBJS)