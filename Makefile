CC=gcc
DBGFLAGS=-g -DDEBUG
CFLAGS=-Wall -std=c99 $(DBGFLAGS)

EXE=dns
LOGIN=xgonce00

SRCS=$(EXE).c args.c dns_packet.c
OBJS:=$(SRCS:c=o)

HDRS=base.h args.h dns_packet.h

TEST_DIR=test
DOC_DIR=doc

.phony: all $(EXE) clean test pack unpack

all: $(EXE)

$(EXE): $(OBJS) Makefile
	$(CC) -o $@ $(OBJS)

$(OBJS): %.o: %.c Makefile $(HDRS)
	$(CC) -c $< $(CFLAGS)

test: $(EXE)
	python3 test.py test_cases.json

pack:
	tar -cvf $(LOGIN).tar $(SRCS) $(HDRS) Makefile \
	$(TEST_DIR)/test.py $(TEST_DIR)/test_cases.json \
	$(DOC_DIR)/README.md $(DOC_DIR)/manual.pdf 

unpack:
	tar -xvf $(LOGIN).tar --one-top-level

clean:
	rm -rf $(EXE) $(OBJS) $(LOGIN).tar $(LOGIN)
	