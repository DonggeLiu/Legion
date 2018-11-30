#include <unistd.h>
#include <stdio.h>

unsigned int test(unsigned int x) {
	if (x > 10) {
		return 0;
	}
	else {
		if (x < 5) {
			switch (x) {
			case 1:
				return 1;
				break;
			case 2:
				return 2;
				break;
			default:
				return 3;
			}
		}
		else {
			switch (x) {
			case 5:
				return 4;
				break;
			case 6:
				return 5;
				break;
			default:
				return 6;
			}
		}
	}


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
