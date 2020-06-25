extern int __VERIFIER_nondet_int(void);


unsigned int test(int x) {
	if (x ==  5) {
	    x = 0;
	}
	else{
        x = 1;
	}
	return x;
}


int main(int argc, char * argv[]) {
	int x = __VERIFIER_nondet_int();
	x = test(x);
	return x;
}
