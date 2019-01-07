#include <unistd.h>
#include <stdio.h>


int test(unsigned int x) {
	while (x>32 && x < 64) {
	    x--;
	}
	return x;
}


int main(int argc, char * argv[]) {
	unsigned char x, y;

	read(0, &x, 1);
	read(0, &y, 1);

	if(y > 256-32) {
	    test(x);
	}

	return 0;
}
