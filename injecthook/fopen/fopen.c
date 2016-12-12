#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/epoll.h>

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
int (*old_fopen)(const char *path, const char *mode);

// arm version of hooks
extern int my_fopen_arm(const char *path, const char *mode);

/*  
 *  log function to pass to the hooking library to implement central loggin
 *
 *  see: set_logfunction() in base.h
 */
static void my_log(char *msg)
{
	log("%s", msg)
}

FILE* hookstatusNewFile(const char *path, const char * mode) {
        char re_path[256];
        sprintf(re_path, "/data/local/tmp/status");
        char buffer[BUFFERSIZE];
        FILE *fpold, *fpnew;
        fpold = old_fopen(path, "r");
        fpnew = old_fopen(re_path, "w");
        if (fpold == NULL || fpnew == NULL) {
                log("[E] re-path [%s]failed", path);
                return old_fopen(path, mode);
        }
        while (fgets(buffer, BUFFERSIZE, fpold) != NULL) {
                if (strstr(buffer, "State") != NULL) {
                        fputs("State:\tS (sleeping)\n", fpnew);
                }
                else if (strstr(buffer, "TracerPid") != NULL) {
                        fputs("TracerPid:\t0\n", fpnew);
                } else {
                        fputs(buffer, fpnew);
                }
        }
        fclose(fpold);
        fclose(fpnew);
        log("[*] hookstatusNewFile Success\n");
        fpold = old_fopen(re_path, mode);
        hook_postcall(&eph);
        return fpold;
}

FILE* hookstatNewFile(const char *path, const char * mode){
        char re_path[256];
        sprintf(re_path, "/data/local/tmp/stat");
        char buffer[BUFFERSIZE];
        char c = 'T';
        char *tmp = NULL;
        FILE *fpold, *fpnew;
        fpold = old_fopen(path, "r");
        fpnew = old_fopen(re_path, "w");
	if (fpold == NULL || fpnew == NULL){
                log("[E] re-path [%s]failed", path);
                return old_fopen(path, mode);
        }
        while (fgets(buffer, BUFFERSIZE, fpold) != NULL) {
                if ((tmp = strchr(buffer, c)) != NULL) {
                        *tmp = 'S';
                        fputs(buffer, fpnew);
                }
                else {
                        fputs(buffer, fpnew);
                }
        }
        fclose(fpold);
        fclose(fpnew);
        log("[*] hookstatNewFile Success\n");
        fpold = old_fopen(re_path, mode);
        hook_postcall(&eph);
        return fpold;
}


FILE* my_fopen(const char *path, const char *mode)
{
	old_fopen = (void*)eph.orig;
	hook_precall(&eph);
	if(strstr(path, "status") != NULL){
		log("[*] Traced-anti-status\n");
                return hookstatusNewFile(path, mode);
        }else if(strstr(path, "stat") != NULL){
		log("[*] Traced-anti-stat\n");
                return hookstatNewFile(path, mode);
        }
}

void hook_entry(char *str)
{
	log("%s started\n", __FILE__)
	set_logfunction(my_log);
	hook(&eph, getpid(), "libc.", "fopen", my_fopen_arm, my_fopen);
}
