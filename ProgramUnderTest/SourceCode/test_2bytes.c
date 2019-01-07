#include <unistd.h>
#include <stdio.h>

unsigned int test(unsigned char *buff) {
    if (buff[0] > 100) {
        return 9;
    }
	if (buff[1] > 128) {
		return 8;
	}
	if (buff[1] > 64) {
		return 7;
	}

	if (buff[1] > 32) {
		return 6;
	}
	//
	if (buff[1] > 16) {
		return 5;
	}

	if (buff[1] > 8) {
		return 4;
	}
	if (buff[1] > 4) {
		return 3;
	}
	if (buff[1] > 2) {
		return 2;
	}
	if (buff[1] > 1) {
		return 1;
	}
	return 0;
}


int main(int argc, char * argv[]) {
	unsigned char buff[2];
	int bytes = read(0, buff, sizeof buff);
	unsigned int r = test(buff);
	return r;
}
