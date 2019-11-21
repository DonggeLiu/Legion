#include <stdio.h>

void whatever( void ) __attribute__ ((constructor));

int SIZE = BUFSIZ*10;
char errbuf[BUFSIZ*10];

void whatever(void){
  setbuffer(stderr,errbuf,SIZE);
}
