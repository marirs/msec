// C with a stack buffer, built with and without the stack protector and other flags.
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buffer[64];
    strcpy(buffer, argc > 1 ? argv[1] : "fixture");
    printf("%s\n", buffer);
    return 0;
}
