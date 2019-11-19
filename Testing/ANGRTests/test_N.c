#include <assert.h>
#include <unistd.h>

int test(unsigned int n) {
    if(n == (unsigned) 5)
        return 1;
    return 0;
}


int main ()
{
    unsigned int n;
    read(0, &n, sizeof(n));
    assert(n < (unsigned) 2000);  // n < 4906
    int x[n];
    int y = test(n);
    return y;
}
