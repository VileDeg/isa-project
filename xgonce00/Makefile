CC=gcc
DBGFLAGS=-g -DDEBUG
CFLAGS=-Wall -std=c99 $(DBGFLAGS)

EXE=dns
LOGIN=xgonce00

SRCS=$(EXE).c args.c server.c dns_packet.c pkt_print.c
OBJS:=$(SRCS:c=o)

HDRS=base.h args.h server.h dns_packet.h pkt_print.h

.phony: all $(EXE) clean pack unpack

all: $(EXE)

$(EXE): $(OBJS) Makefile
	$(CC) -o $@ $(OBJS)

$(OBJS): %.o: %.c Makefile $(HDRS)
	$(CC) -c $< $(CFLAGS)

pack:
	tar -cvf $(LOGIN).tar $(SRCS) $(HDRS) Makefile

unpack:
	tar -xvf $(LOGIN).tar --one-top-level

clean:
	rm -rf $(EXE) $(OBJS) $(LOGIN).tar $(LOGIN)
	