/*
 *  aul
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>, Jaeho Lee <jaeho81.lee@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <glib.h>
#include "simple_util.h"
#include "aul_zone.h"

#define BINSH_NAME	"/bin/sh"
#define BINSH_SIZE	7
#define VALGRIND_NAME	"/home/developer/sdk_tools/valgrind/usr/bin/valgrind"
#define VALGRIND_SIZE	51
#define BASH_NAME	"/bin/bash"
#define BASH_SIZE	9
#define OPROFILE_NAME	"/usr/bin/oprofile_command"
#define OPROFILE_SIZE	25
#define OPTION_VALGRIND_NAME	"valgrind"
#define OPTION_VALGRIND_SIZE	8


#define PROC_STAT_GID_POS	5


static inline int __read_proc(const char *path, char *buf, int size);
static inline int __find_pid_by_cmdline(const char *dname,
				      const char *cmdline, void *priv);
static inline int __get_pgid_from_stat(int pid);


static inline int __read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

static inline int __find_pid_by_cmdline(const char *dname,
				      const char *cmdline, void *priv)
{
	char *apppath;
	int pid = 0;

	apppath = (char *)priv;
	if (strncmp(cmdline, apppath, MAX_LOCAL_BUFSZ-1) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
	}

	return pid;
}

int __proc_check_app(const char *path, int pid)
{
	char buf[MAX_LOCAL_BUFSZ] = {0};
	char *cmdline;
	int ret = 0;

	if (!path || pid < 1)
		return 0;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return 0;

	/* support app launched by shell script */
	cmdline = buf;
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0) {
		cmdline = &buf[BINSH_SIZE + 1];
	} else if (strncmp(buf, BASH_NAME, BASH_SIZE) == 0) {
		if (strncmp(&buf[BASH_SIZE + OPROFILE_SIZE + 2], OPTION_VALGRIND_NAME, OPTION_VALGRIND_SIZE) == 0) {
			cmdline = &buf[BASH_SIZE + OPROFILE_SIZE + OPTION_VALGRIND_SIZE + 3];
		}
	}

	if (strncmp(cmdline, path, MAX_LOCAL_BUFSZ - 1) == 0)
		return pid;

	return 0;
}

extern gboolean app_group_is_sub_app(int pid);

int __proc_iter_cmdline(
	int (*iterfunc)(const char *dname, const char *cmdline, void *priv),
		    void *priv)
{
	DIR *dp = NULL;
	struct dirent *dentry = NULL;
	int pid = 0;
	int ret = 0;
	char buf[MAX_LOCAL_BUFSZ] = {0,};

	snprintf(buf, sizeof(buf), "%sproc", _get_root_path());
	dp = opendir(buf);
	if (dp == NULL) {
		return -1;
	}

	if (iterfunc == NULL)
		iterfunc = __find_pid_by_cmdline;

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(buf, sizeof(buf), "%sproc/%s/cmdline", _get_root_path(), dentry->d_name);
		ret = __read_proc(buf, buf, sizeof(buf));
		if (ret <= 0)
			continue;

		/* support app launched by shell script*/
		if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0) {
			pid = iterfunc(dentry->d_name, &buf[BINSH_SIZE + 1], priv);
		}
		else if (strncmp(buf, VALGRIND_NAME, VALGRIND_SIZE) == 0) {
			char* ptr = buf + VALGRIND_SIZE + 1;

			// buf comes with double null-terminated string
			while (1) {
				while (*ptr) {
					ptr++;
				}
				ptr++;

				if (*ptr == '\0') {	// double null
					break;
				}

				// ignore trailing "--"
				if (strncmp(ptr, "-", 1) != 0) {
					break;
				}
			};

			_D("cmdline is [%s]", ptr);
			pid = iterfunc(dentry->d_name, ptr, priv);
		}
		else {
			pid = iterfunc(dentry->d_name, buf, priv);
		}

		if (pid > 0) {
			if (app_group_is_sub_app(pid))
				continue;

			closedir(dp);
			return pid;
		}
	}

	closedir(dp);
	return -1;
}

char *__proc_get_cmdline_bypid(int pid)
{
#define MAX_CMD_BUFSZ 1024

	char buf[MAX_CMD_BUFSZ];
	int ret;

	snprintf(buf, sizeof(buf), "%sproc/%d/cmdline", _get_root_path(), pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* support app launched by shell script*/
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0) {
		return strdup(&buf[BINSH_SIZE + 1]);
	}
	else if (strncmp(buf, VALGRIND_NAME, VALGRIND_SIZE) == 0) {
		char* ptr = buf;

		// buf comes with double null-terminated string
		while (1) {
			while (*ptr) {
				ptr++;
			}
			ptr++;

			if (*ptr == '\0')
				break;

			// ignore trailing "--"
			if (strncmp(ptr, "-", 1) != 0)
				break;
		};

		return strdup(ptr);
	}
	else if (strncmp(buf, BASH_NAME, BASH_SIZE) == 0) {
		if (strncmp(&buf[BASH_SIZE + 1], OPROFILE_NAME, OPROFILE_SIZE) == 0) {
			if (strncmp(&buf[BASH_SIZE + OPROFILE_SIZE + 2], OPTION_VALGRIND_NAME, OPTION_VALGRIND_SIZE) == 0) {
				return strdup(&buf[BASH_SIZE + OPROFILE_SIZE + OPTION_VALGRIND_SIZE + 3]);
			}
		}
	}

	return strdup(buf);
}

static inline int __get_pgid_from_stat(int pid)
{
	char buf[MAX_LOCAL_BUFSZ];
	char *str = NULL;
	int ret;
	int i;
	int count = 0;

	if (pid <= 1)
		return -1;

	snprintf(buf, sizeof(buf), "%sproc/%d/stat", _get_root_path(), pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret < 0)
		return -1;

	for (i = 0; i < (ret - 1); i++) {
		if (buf[i] == ' ') {
			count++;
			if (count == PROC_STAT_GID_POS - 1)
				str = &(buf[i + 1]);
			else if (count == PROC_STAT_GID_POS) {
				buf[i] = 0;
				break;
			}
		}
	}

	if (count == PROC_STAT_GID_POS && str)
		pid = atoi(str);
	else
		pid = -1;

	return pid;
}

int __proc_iter_pgid(int pgid, int (*iterfunc) (int pid, void *priv),
		     void *priv)
{
	DIR *dp;
	struct dirent *dentry;
	int _pgid;
	int ret = -1;
	char buf[MAX_LOCAL_BUFSZ] = { 0, };

	snprintf(buf, sizeof(buf), "%sproc", _get_root_path());
	dp = opendir(buf);
	if (dp == NULL) {
		return -1;
	}

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		_pgid = __get_pgid_from_stat(atoi(dentry->d_name));
		if (pgid == _pgid) {
			ret = iterfunc(atoi(dentry->d_name), priv);
			if (ret >= 0)
				break;
		}
	}

	closedir(dp);
	return ret;
}

void __trm_app_info_send_socket(char *write_buf)
{
        const char trm_socket_for_app_info[] = "/dev/socket/app_info";
        int socket_fd = 0;
        int ret = 0;
        struct sockaddr_un addr;
	char buf[MAX_LOCAL_BUFSZ] = { 0, };

	_D("__trm_app_info_send_socket");

	snprintf(buf, sizeof(buf), "%s%s", _get_root_path(), trm_socket_for_app_info);

        if (access(buf, F_OK) != 0) {
		_E("access");
		goto trm_end;
	}

        socket_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
        if (socket_fd < 0) {
		_E("socket");
                goto trm_end;
        }

        memset(&addr, 0, sizeof(addr));
        snprintf(addr.sun_path, UNIX_PATH_MAX, "%s", buf);
        addr.sun_family = AF_LOCAL;

        ret = connect(socket_fd, (struct sockaddr *) &addr ,sizeof(sa_family_t) + strlen(buf) );
        if (ret != 0) {
                close(socket_fd);
                goto trm_end;
        }

        ret = send(socket_fd, write_buf, strlen(write_buf), MSG_DONTWAIT | MSG_NOSIGNAL);
	if (ret < 0)
		_E("Unable to send data. Error is %s\n",strerror(errno));
	else
		_D("send");

        close(socket_fd);
trm_end:
        return;
}

