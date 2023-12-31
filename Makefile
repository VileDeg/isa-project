CC=gcc
# DBGFLAGS=-g -DDEBUG
DBGFLAGS=-g
CFLAGS=-Wall -std=c99 $(DBGFLAGS)

EXE=dns
LOGIN=xgonce00

SRCS=$(EXE).c args.c dns_packet.c
OBJS:=$(SRCS:c=o)

HDRS=base.h args.h dns_packet.h

TEST_DIR=test
DOC_DIR=.

.PHONY: all clean test pack unpack

all: $(EXE)

$(EXE): $(OBJS) Makefile
	$(CC) -o $@ $(OBJS)

%.o: %.c Makefile $(HDRS)
	$(CC) -c $< $(CFLAGS)

pack:
	tar -cvf $(LOGIN).tar $(SRCS) $(HDRS) Makefile \
	$(TEST_DIR)/test.py $(TEST_DIR)/test_cases.json \
	README.md $(DOC_DIR)/manual.pdf 
 
test: $(EXE)
	python3 $(TEST_DIR)/test.py $(TEST_DIR)/test_cases.json

unpack:
	mkdir $(LOGIN)
	tar -xvf $(LOGIN).tar -C $(LOGIN)

clean:
	rm -rf $(EXE) $(OBJS) $(LOGIN).tar $(LOGIN)
	
