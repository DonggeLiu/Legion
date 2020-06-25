#include <stdio.h>
#include <stdlib.h>


void register_atexit( void ) __attribute__ ((constructor));


#ifndef MAX_TRACE_LEN
    #define MAX_TRACE_LEN 42
#endif

#ifndef VERBOSE
    #define VERBOSE 0
#endif

void* trace[MAX_TRACE_LEN];
int trace_index = 0;


void save_to_errbuf(void* address) {
    if (MAX_TRACE_LEN && trace_index>= MAX_TRACE_LEN){
        if (VERBOSE) printf("Max trace length %d reached\n", (int) MAX_TRACE_LEN);
        exit(0);
    }
    if (VERBOSE) printf("Saving %p to array\n", address);
    trace[trace_index] = address;
    trace_index++;
}


void print_errbuff(void) {
    fwrite(trace, sizeof(trace[0]), trace_index, stderr);
    for(int j=0; j<trace_index; j++) {
        if (VERBOSE) printf("Printing %p to stderr\n", trace[j]);
    }
}


void register_atexit(void) {
    atexit(print_errbuff);
}
