extern int __VERIFIER_nondet_int(void);

unsigned int test(int x) {
	switch (x){
	    case 2:
	        x++;
	        break;
	    case 1:
	        x--;
	        break;
	    case 3:
	        x=x;
	        break;
	    default:
	        x = x;
	}

	return 0;
}


int main(int argc, char * argv[]) {
	int x = __VERIFIER_nondet_int();
	test(x);
	return 0;
}
