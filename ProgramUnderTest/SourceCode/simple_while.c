#include <unistd.h>
#include <stdio.h>

int region1(unsigned int n) {
	while (n>32 && n < 40)
	    n--;
	return n;
}

int region2(unsigned int n) {
	while (n > 100 && n < 108)
		n--;
	return n;
}

int main(int argc, char * argv[]) {

	unsigned char buff[2];
	int bytes = read(0, buff, sizeof buff);
	if (buff[0] == 25 && ((buff[0] + buff[1])<65)) {
	    region1(buff[1]);
	}
	region2(buff[0]);
	return 0;
}
