#include <unistd.h>
#include <stdio.h>


int test(unsigned int x) {
	while (x>110) {
	    x--;
	}
	return x;
}


int main(int argc, char * argv[]) {
	unsigned char x;

	// int n;
	// n = read(0, &x, 1);
	// printf("read %d bytes, x = %c\n", n, x);
	read(0, &x, 1);
	unsigned int r = test(x);
	return x;
}
