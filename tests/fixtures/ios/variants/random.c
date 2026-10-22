// msec's rule-variant fixture (build_rule_variants.sh): C library random numbers, in an
// executable that also searches /usr/local/lib for libraries.
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  srand((unsigned)argc);
  printf("%d\n", rand());
  return 0;
}
