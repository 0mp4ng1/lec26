// main.cpp
#include <stdio.h>
#include <stdint.h>
#include "sum.h"
#include "btol.h"

int main(int argc, char* argv[]) {
	FILE *f1, *f2;
	uint32_t a, b, a1, b1, s;
	f1 = fopen(argv[1], "rb"); 
	f2 = fopen(argv[2], "rb"); 
	fread(&a, sizeof(uint32_t),1, f1);
	fread(&b, sizeof(uint32_t),1, f2);
	a1 = btol(a);
	b1 = btol(b);
	s = sum(a1, b1);
	printf("%d(%#x) + %d(%#x) = %d(%#x)\n", a1, a1, b1, b1, s, s);
	fclose(f1);
	fclose(f2);
}
