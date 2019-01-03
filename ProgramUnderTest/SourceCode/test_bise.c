#include <unistd.h>
#include <stdio.h>

unsigned int test(unsigned int x) {
	if (x <= 255) {
        if (x <= 128) {
            if (x <= 64) {
                if (x <= 32) {
                    if (x <= 16) {
                        if (x <= 8) {
                            if (x <= 4) {
                                if (x <= 2) {
                                    if (x <= 1) {
                                        return 1;
                                    }
                                    return 2;
                                }
                                return 3;
                            }
                            return 4;
                        }
                        return 5;
                    }
                    return 6;
                }
                return 7;
            }
            return 8;
        }
		return 9;
	}
	return 0;
}


int main(int argc, char * argv[]) {
	unsigned char x;
	// int n;
	// n = read(0, &x, 1);
	// printf("read %d bytes, x = %c\n", n, x);
	read(0, &x, 1);
	unsigned int r = test(x);
	return r;
}
