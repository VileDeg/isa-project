CC=gcc
DBGFLAGS=-g -DDEBUG
CFLAGS=-Wall -std=c99 $(DBGFLAGS)

EXE=dns

SRCS=$(EXE).c args.c dns_packet.c pkt_print.c
OBJS:=$(SRCS:c=o)

HDRS=base.h args.h dns_packet.h pkt_print.h

.phony: all $(EXE) clean

all: $(EXE)

$(EXE): $(OBJS) Makefile
	$(CC) -o $@ $(OBJS)

$(OBJS): %.o: %.c Makefile $(HDRS)
	$(CC) -c $< $(CFLAGS)

clean:
	rm -f $(EXE) $(OBJS)