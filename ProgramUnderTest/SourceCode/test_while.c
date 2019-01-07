#include <unistd.h>
#include <stdio.h>


unsigned int test(unsigned int x) {
	int i = 256;
	while (x < i) {
		if (x > (i / 2)) {
			return i;
		}
		i -= 8;
	}
	return i;
}


int main(int argc, char * argv[]) {
	unsigned char x,y;

	// int n;
	// n = read(0, &x, 1);
	// printf("read %d bytes, x = %c\n", n, x);
	read(0, &x, 1);
	read(0, &y, 1);
	if (y > 240)
	    test(x);
	else {

	}
	return 0;
}
