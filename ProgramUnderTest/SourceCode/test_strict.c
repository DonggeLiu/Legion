#include <unistd.h>
#include <stdio.h>

unsigned int test(unsigned int x) {
	if (x > 255) {
		return 0;
	}
	if (x == 147) {
        return 1;
	}
	if (x == 111) {
	    return 2;
	}
	if (x == 37) {
	    return 3;
	}
	if (x == 23) {
	    return 4;
	}
	if (x == 13) {
	    return 5;
	}
	if (x == 6) {
	    return 6;
	}
	if (x == 3) {
	    return 7;
	}
	if (x == 1) {
		return 8;
	}
	return 9;
}


int main(int argc, char * argv[]) {
	unsigned char x;
	read(0, &x, 1);
	unsigned int r = test(x);
	return r;
}
