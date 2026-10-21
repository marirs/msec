// A framework that reads file timestamps; its own privacy manifest does not declare them.
#include <sys/stat.h>

long fixture_lib_size(int descriptor) {
    struct stat info;
    return fstat(descriptor, &info) == 0 ? (long)info.st_size : -1;
}
