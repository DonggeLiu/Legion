extern int __VERIFIER_nondet_int(void);

int N;

int test(int x) {
    int y = 0;
        if (x < 0) {
        y = 2;
    }
    else if (x == 0) {
        y = 0;
    }
    else if (x > 0) {
        y = 1;
    }
    return y;
}


int main ()
{
    int y;
    N = __VERIFIER_nondet_int();
    int x[N];
    y = test(N);
  return y;
}
