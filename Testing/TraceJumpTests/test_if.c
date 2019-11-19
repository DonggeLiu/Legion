extern int __VERIFIER_nondet_int(void);


unsigned int test(int x) {
	if (x > 5) {
	    x = 6;
	}
	else{
        x = 7;
	}
	return x;
}


int main(int argc, char * argv[]) {
	int x = __VERIFIER_nondet_int();
    test(x);
	return x;
}
