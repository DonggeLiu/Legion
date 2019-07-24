#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

void __VERIFIER_error() {
	exit(101);
}

int __VERIFIER_nondet_int() {
    int x = 0;
    read(0, (char *)&x, sizeof(x));
    printf("<input type=\"int\">%d</input>", x);
	return x;
}

short __VERIFIER_nondet_short() {
	short x = 0;
	read(0, (char *)&x, sizeof(x));
    printf("<input type=\"short\">%hd</input>", x);
	return x;
}

unsigned long __VERIFIER_nondet_ulong() {
	unsigned long x = 0;
	read(0, (char *)&x, sizeof(x));
    printf("<input type=\"unsigned long\">%lu</input>", x);
	return x;
}

float __VERIFIER_nondet_float() {
	float x = 0.0;
	read(0, (char *)&x, sizeof(x));
    printf("<input type=\"float\">%f</input>", x);
	return x;
}

char __VERIFIER_nondet_char() {
	char x = 0;
	read(0, &x, sizeof(x));
    printf("<input type=\"char\">%hhd</input>", x);
	return x;
}

int __VERIFIER_assume(int b) {
	return b;
}

// int __VERIFIER_nondet_const_char_pointer() {

// }

//int __VERIFIER_nondet_S8() {
	// How many bytes in S8?
//	return __my_read_int(8);
//}
