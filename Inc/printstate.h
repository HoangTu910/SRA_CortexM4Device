#ifndef PRINTSTATE_H_
#define PRINTSTATE_H_

#include "ascon.h"

void print(const char* text);
void printbytes(const char* text, const uint8_t* b, uint64_t len);
void printword(const char* text, const uint64_t x);
void printstate(const char* text, const ascon_state_t* s);

#endif /* PRINTSTATE_H_ */

//void print_bytes(const char* label, const unsigned char* data, size_t len);
