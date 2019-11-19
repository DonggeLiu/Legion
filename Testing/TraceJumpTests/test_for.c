extern int __VERIFIER_nondet_int(void);


unsigned int test(int x) {
	int i;
	for (i=0; i < x; i++){
        	continue;
	}
	return 0;
}


int main(int argc, char * argv[]) {
	int x = __VERIFIER_nondet_int();

	if (x < 5) {
		test(x);
	}
	return 0;
}
