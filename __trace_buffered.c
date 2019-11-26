#include <stdio.h>

void set_errbuf( void ) __attribute__ ((constructor));

// Having larger buffers (to 1000x) did not speed things up in experiments
char errbuf[BUFSIZ];

void set_errbuf(void){
    setbuffer(stderr,errbuf,BUFSIZ);
//    setbuf(stderr, errbuf);
//    setvbuf(stderr,errbuf, _IOFBF, sizeof(errbuf));
}
