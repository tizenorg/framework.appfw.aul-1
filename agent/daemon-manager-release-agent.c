#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "app_sock.h"
#include "aul_util.h"

#define LOG_PATH "/tmp/dmlaunch.err"

static void elog(const char *fmt, ...)
{
	FILE *fp;
	va_list ap;

	fp = fopen(LOG_PATH, "w+");
	if (!fp)
		return;

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);

	fclose(fp);
}


int main(int argc, char *argv[])
{
	int ret = 0;

	elog("release agent : [%d:%s]\n", argc, argv[1]);

	if (argc < 2) {
		elog("usage) %s path\n", argv[0]);
		return 1;
	}

	ret = __app_send_raw(AUL_UTIL_PID, APP_RELEASED, (unsigned char*)argv[1], strlen(argv[1]));

	elog("release agent : %d\n", ret);

	return 0;
}

