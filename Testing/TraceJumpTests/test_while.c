#include <stdio.h>

extern int __VERIFIER_nondet_uint(void);


unsigned int test(int x) {
	while (x)
	{
		x --;
//		fwrite(&x, 8, 1, stderr);
	}
	return 0;
}


int main(int argc, char * argv[]) {
//    printf("%d", BUFSIZ);
//    char buf[BUFSIZ];
//    setbuf(stderr, buf);
	unsigned int x = __VERIFIER_nondet_uint();
	test(x);
	return 0;
}
