#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <stdlib.h>

#include "../base/hook.h"
#include "../base/base.h"

#undef log

#define log(...) \
{FILE *fp = fopen("/data/local/tmp/Hook.log", "a+"); if (fp) {\
	fprintf(fp, __VA_ARGS__);\
	fclose(fp);}}

#define BUFFERSIZE 512 
// this file is going to be compiled into a thumb mode binary


static struct hook_t eph;
//old fopen
int (*old_open)(const char *pathname, int flags);

// arm version of hooks
extern int my_open_arm(const char *pathname, int flags);

/*  
 *  log function to pass to the hooking library to implement central loggin
 *
 *  see: set_logfunction() in base.h
 */
static void my_log(char *msg)
{
	log("%s", msg)
}

ssize_t	read_line(int fd, void *vptr, ssize_t maxlen)
{
	ssize_t n, rc;
	char c, *ptr;

	ptr = vptr;
	for (n = 1; n < maxlen; n++)
	{
again:
		if ((rc = read(fd, &c, 1)) == 1)
		{
			*ptr++ = c;
			if (c == '\n')
				break;
		}
		else if (rc == 0)
		{
			*ptr = 0;
			return(n - 1);
		} 
		else
		{
			if (errno == EINTR)
				goto again;
			return(-1);
		}
	}
	*ptr = 0;
	return(n);
}

int hookstatusNewFile(const char *pathname, int flags) {
	char re_path[256];
	sprintf(re_path, "/data/local/tmp/status");
	char buffer[BUFFERSIZE];
	int fpold, fpnew, n;
	fpold = old_open(pathname, O_RDWR);
	fpnew = open(re_path, O_CREAT | O_TRUNC | O_RDWR, 777);
	if (fpold == -1 || fpnew == -1) {
		log("[E] re-path [%s]failed", pathname);
		return old_open(pathname, flags);
	}
	chmod(re_path, S_IRWXU | S_IRWXG | S_IRWXO);
	while ((n = read_line(fpold, buffer, BUFFERSIZE)) != 0) {
		if (strstr(buffer, "State") != NULL) {
			if(write(fpnew, "State:\tS (sleeping)\n", sizeof("State:\tS (sleeping)\n")) != sizeof("State:\tS (sleeping)\n")){
				log("write stat error\n");
			}
		}
		else if (strstr(buffer, "TracerPid") != NULL) {
			if(write(fpnew, "TracerPid:\t0\n", sizeof("TracerPid:\t0\n")) != sizeof("TracerPid:\t0\n")){
				log("write TracerPid error\n");
			}
		} else {
			if(write(fpnew, buffer, n) != n){
				log("write error\n");
			}
		}
	}
	close(fpold);
	close(fpnew);
	log("[*] hookstatusNewFile Success\n");
	fpold = old_open(re_path, flags);
	hook_postcall(&eph);
	return fpold;
}

int hookstatNewFile(const char *pathname, int flags){
	char re_path[256];
	sprintf(re_path, "/data/local/tmp/stat");
	char buffer[BUFFERSIZE];
	char c = 'T';
	char *tmp = NULL;
	int fpold, fpnew, n;
	fpold = old_open(pathname, O_RDONLY);
	fpnew = open(re_path,  O_CREAT | O_TRUNC | O_RDWR, 0666);
	if (fpold == -1 || fpnew == -1){
		log("[E] re-path [%s]failed", pathname);
		return old_open(pathname, flags);
	}
	chmod(re_path, S_IRWXU | S_IRWXG | S_IRWXO);
	while ((n = read(fpold, buffer, BUFFERSIZE)) != 0) {
		if ((tmp = strchr(buffer, c)) != NULL) {
			*tmp = 'S';
			write(fpnew, buffer, n);
		}
		else {
			write(fpnew, buffer, n);
		}
	}
	close(fpold);
	close(fpnew);
	log("[*] hookstatNewFile Success\n");
	fpold = old_open(re_path, flags);
	hook_postcall(&eph);
	return fpold;
}


int my_open(const char *pathname, int flags)
{
	old_open = (void*)eph.orig;
	hook_precall(&eph);

	if(strstr(pathname, "status") != NULL){
		log("[*] Traced-anti-status\n");
		return hookstatusNewFile(pathname, flags);
	}else if(strstr(pathname, "stat") != NULL){
		log("[*] Traced-anti-stat\n");
		return hookstatNewFile(pathname, flags);
	}
}

void hook_entry(char *str)
{
	log("%s started\n", __FILE__)
		set_logfunction(my_log);
	hook(&eph, getpid(), "libc.", "open", my_open_arm, my_open);
}
