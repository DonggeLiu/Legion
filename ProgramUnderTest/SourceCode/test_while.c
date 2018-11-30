#include <unistd.h>
#include <stdio.h>


unsigned int test(unsigned int x) {
	int i = 256;
	while (x < i) {
		if (x > (i / 2)) {
			return i;
		}
		i /= 2;
	}
	return i;
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
