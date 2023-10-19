#include <stdio.h>
#include <ctype.h>

#include "pkt_print.h"

// Print 16 bytes in hex and ascii
void print_packet_line(const unsigned char* line, int len, int offset) {
	/* Function is inspired by https://www.tcpdump.org/other/sniffex.c [4] */

	int i;
	int gap;
	const unsigned char *ch;

	// Offset
	printf("0x%04x: ", offset);

	// Hex values
	ch = line;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
	}
	// Print space to handle line less than 8 bytes
	if (len < 8)
		printf(" ");

	// Fill hex gap with spaces if not full line
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}

	// ASCII (if printable) otherwise '.'
	ch = line;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
		if (i == 7)
			printf(" ");
	}

	printf("\n");
}

void print_packet(const unsigned char* packet, int len) {
	/* Function is inspired by https://www.tcpdump.org/other/sniffex.c [4] */

	int len_rem = len;
	int line_width = 16;			// Number of bytes per line
	int line_len;
	int offset = 0;					// Zero-based offset counter
	const unsigned char *ch = packet;

	if (len <= 0)
		return;

	printf("\n");

	// Data fits on one line
	if (len <= line_width) {
		print_packet_line(ch, len, offset);
		return;
	}

	// Data spans multiple lines
	while (1) {
		// Current line length
		line_len = line_width % len_rem;

		print_packet_line(ch, line_len, offset);
		// Total remaining
		len_rem = len_rem - line_len;
		// Shift pointer to remaining bytes to print
		ch = ch + line_len;

		offset = offset + line_width;
		// Check if we have line width chars or less
		if (len_rem <= line_width) {
			// Print last line
			print_packet_line(ch, len_rem, offset);
			break;
		}
	}
}
