extern int __VERIFIER_nondet_int(void);

int N;

int test(int n) {
    if(n)
        return 1;
    return 0;
}


int main ()
{
    N = __VERIFIER_nondet_int();
    int x[N];
    test(N);
    return 0;
}
