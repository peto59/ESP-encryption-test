#include "tests.h"

int hex_tests(encryption_t *handle){
    const char input1[] = "9dc38838f0eb226c0529fc618bd608710089ce3afc0837bdc9f539fc9f9805dd";
    size_t ilen1 = 64;

    unsigned char output1[512];
    size_t olen1 = 512;

    int ret = (*(handle->hex_handle.decode))(NULL, (const unsigned char *)input1, ilen1, output1, &olen1);
    
    printf("hex_test returned %i\n", ret);

    return ret;
}
