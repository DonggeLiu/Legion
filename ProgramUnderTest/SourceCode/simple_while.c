#include <unistd.h>
#include <stdio.h>


int test(unsigned int y) {
	while (y>32 && y < 40) {
	    y--;
	}
	return y;
}


int main(int argc, char * argv[]) {

	unsigned char buff[2];
	int bytes = read(0, buff, sizeof buff);
	if (buff[0] > 200) {
	    test(buff[1]);
	}
	return 0;
}
