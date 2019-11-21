#include <stdio.h>

void whatever( void ) __attribute__ ((constructor));

// Having larger buffers (to 1000x) did not speed things up in experiments
char errbuf[BUFSIZ];

void set_errbuf(void){
    setvbuf(stderr,errbuf, _IOFBF, sizeof(errbuf));
}
