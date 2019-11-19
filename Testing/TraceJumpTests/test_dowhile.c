extern int __VERIFIER_nondet_int(void);


unsigned int test(int x) {
	do  {
	    x--;
	} while (x > 0 && x < 8);

	return 0;
}


int main(int argc, char * argv[]) {
    int x = __VERIFIER_nondet_int();
	test(x);
	return 0;
}
