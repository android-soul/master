
#include <sys/types.h>

extern int my_fopen(const char *path, const char *mode);

int my_fopen_arm(const char *path, const char *mode)
{
	return my_fopen(path,mode);
}
