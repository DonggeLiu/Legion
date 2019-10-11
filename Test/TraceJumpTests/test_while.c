extern int __VERIFIER_nondet_int(void);


unsigned int test(int x) {
	while (x < 8 && x > 0)
	{
		x ++;
	}
	return 0;
}


int main(int argc, char * argv[]) {
	int x = __VERIFIER_nondet_int();
	test(x);
	return 0;
}
