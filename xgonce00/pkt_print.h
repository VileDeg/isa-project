#ifndef __PKT_PRINT_H__
#define __PKT_PRINT_H__

// Print 16 bytes in hex and ascii
void print_packet_line(const unsigned char* line, int len, int offset);

void print_packet(const unsigned char* packet, int len);

#endif // !__PKT_PRINT_H__