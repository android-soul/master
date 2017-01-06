#include <sys/types.h>

extern int my_open(const char *pathname, int flags);

int my_open_arm(const char *pathname, int flags)
{
	return my_open(pathname,flags);
}
