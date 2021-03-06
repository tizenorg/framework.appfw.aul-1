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


/*
 * simple AUL daemon - launchpad 
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <X11/Xlib.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/prctl.h>
#include <malloc.h>

#include "app_sock.h"
#include "aul.h"

#include "config.h"

#include "menu_db_util.h"
#include "simple_util.h"
#include "access_control.h"
#include "preload.h"
#include "preexec.h"
#include "perf.h"
#include "sigchild.h"
#include "aul_util.h"

#include "heap_dbg.h"

#include "util_x.h"

#include "gl.h"

#include <app-checker.h>
#include <sqlite3.h>

#define _static_ static inline
#define POLLFD_MAX 1
#define SQLITE_FLUSH_MAX	(1048576)	/* (1024*1024) */
#define AUL_POLL_CNT		15
#define AUL_PR_NAME			16
#define PATH_APP_ROOT "/opt/apps"
#define PATH_DATA "/data"
#define SDK_CODE_COVERAGE "CODE_COVERAGE"
#define SDK_DYNAMIC_ANALYSIS "DYNAMIC_ANALYSIS"
#define PATH_DA_SO "/home/developer/sdk_tools/da/da_probe.so"


static char *launchpad_cmdline;
static int initialized = 0;


_static_ void __set_oom();
_static_ void __set_env(app_info_from_db * menu_info, bundle * kb);
_static_ int __prepare_exec(const char *pkg_name,
			    const char *app_path, app_info_from_db * menu_info,
			    bundle * kb);
_static_ int __fake_launch_app(int cmd, int pid, bundle * kb);
_static_ char **__create_argc_argv(bundle * kb, int *margc);
_static_ int __normal_fork_exec(int argc, char **argv);
_static_ void __real_launch(const char *app_path, bundle * kb);
_static_ void __add_history(int caller, int callee, const char *pkgname,
				bundle *b, const char *app_path);
static inline int __parser(const char *arg, char *out, int out_size);
_static_ void __modify_bundle(bundle * kb, int caller_pid,
			    app_info_from_db * menu_info, int cmd);
_static_ int __child_raise_win_by_x(int pid, void *priv);
_static_ int __raise_win_by_x(int pid);
_static_ int __send_to_sigkill(int pid);
_static_ int __term_app(int pid);
_static_ int __resume_app(int pid);
_static_ int __app_process_by_pid(int cmd, 
	const char *pkg_name, struct ucred *cr);
_static_ int __nofork_processing(int cmd, int pid, bundle * kb);
_static_ void __real_send(int clifd, int ret);
_static_ void __send_result_to_caller(int clifd, int ret);
_static_ void __launchpad_main_loop(int main_fd);
_static_ int __launchpad_pre_init(int argc, char **argv);
_static_ int __launchpad_post_init();

extern ail_error_e ail_db_close(void);



_static_ void __set_oom()
{
	char buf[MAX_LOCAL_BUFSZ];
	FILE *fp;

	/* we should reset oomadj value as default because child 
	inherits from parent oom_adj*/
	snprintf(buf, MAX_LOCAL_BUFSZ, "/proc/%d/oom_adj", getpid());
	fp = fopen(buf, "w");
	if (fp == NULL)
		return;
	fprintf(fp, "%d", -16);
	fclose(fp);
}

_static_ void __set_sdk_env(app_info_from_db* menu_info, char* str) {
	char buf[MAX_LOCAL_BUFSZ];
	int ret;

	_D("key : %s / value : %s", AUL_K_SDK, str);
	/* http://gcc.gnu.org/onlinedocs/gcc/Cross_002dprofiling.html*/
	/* GCOV_PREFIX contains the prefix to add to the absolute paths in the object file. */
	/*		Prefix can be absolute, or relative. The default is no prefix.  */
	/* GCOV_PREFIX_STRIP indicates the how many initial directory names */
	/*		to stripoff the hardwired absolute paths. Default value is 0. */
	if (strncmp(str, SDK_CODE_COVERAGE, strlen(str)) == 0) {
		snprintf(buf, MAX_LOCAL_BUFSZ, PATH_APP_ROOT"/%s"PATH_DATA, _get_pkgname(menu_info));
		ret = setenv("GCOV_PREFIX", buf, 1);
		_D("GCOV_PREFIX : %d", ret);
		ret = setenv("GCOV_PREFIX_STRIP", "4096", 1);
		_D("GCOV_PREFIX_STRIP : %d", ret);
	} else if (strncmp(str, SDK_DYNAMIC_ANALYSIS, strlen(str)) == 0) {
		ret = setenv("LD_PRELOAD", PATH_DA_SO, 1);
		_D("LD_PRELOAD : %d", ret);
	}
}


_static_ void __set_env(app_info_from_db * menu_info, bundle * kb)
{
	const char *str;
	const char **str_array;
	int len;
	int i;

	setenv("PKG_NAME", _get_pkgname(menu_info), 1);

	USE_ENGINE("gl")

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str != NULL)
		setenv("APP_START_TIME", str, 1);

	if(bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
		if(str_array != NULL) {
			for (i = 0; i < len; i++) {
				_D("index : [%d]", i);
				__set_sdk_env(menu_info, (char *)str_array[i]);
			}
		}
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if(str != NULL) {
			__set_sdk_env(menu_info, (char *)str);
		}
	}
}

_static_ int __prepare_exec(const char *pkg_name,
			    const char *app_path, app_info_from_db * menu_info,
			    bundle * kb)
{
	char *file_name;
	char process_name[AUL_PR_NAME];

	/* Set new session ID & new process group ID*/
	/* In linux, child can set new session ID without check permission */
	/* TODO : should be add to check permission in the kernel*/
	setsid();

	__preexec_run(menu_info->pkg_type, pkg_name, app_path);

	/* SET OOM*/
	__set_oom();

	/* SET SMACK LABEL */
	__set_smack((char *)app_path);

	/* SET DAC*/
	if (__set_dac(pkg_name) < 0) {
		_D("fail to set DAC - check your package's credential\n");
		return -1;
	}
	/* SET DUMPABLE - for coredump*/
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME*/
	if (app_path == NULL) {
		_D("app_path should not be NULL - check menu db");
		return -1;
	}
	file_name = strrchr(app_path, '/') + 1;
	if (file_name == NULL) {
		_D("can't locate file name to execute");
		return -1;
	}
	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	/* SET ENVIROMENT*/
	__set_env(menu_info, kb);

	return 0;
}

_static_ int __fake_launch_app(int cmd, int pid, bundle * kb)
{
	int datalen;
	int ret;
	bundle_raw *kb_data;

	bundle_encode(kb, &kb_data, &datalen);
	if ((ret = __app_send_raw(pid, cmd, kb_data, datalen)) < 0)
		_E("error request fake launch - error code = %d", ret);
	free(kb_data);
	return ret;
}

_static_ char **__create_argc_argv(bundle * kb, int *margc)
{
	char **argv;
	int argc;

	argc = bundle_export_to_argv(kb, &argv);

	*margc = argc;
	return argv;
}

_static_ int __normal_fork_exec(int argc, char **argv)
{
	_D("start real fork and exec\n");

	if (execv(argv[0], argv) < 0) {	/* Flawfinder: ignore */
		if (errno == EACCES)
			_E("such a file is no executable - %s", argv[0]);
		else
			_E("unknown executable error - %s", argv[0]);
		return -1;
	}
	/* never reach*/
	return 0;
}

_static_ void __real_launch(const char *app_path, bundle * kb)
{
	int app_argc;
	char **app_argv;
	int i;

	app_argv = __create_argc_argv(kb, &app_argc);
	app_argv[0] = strdup(app_path);

	for (i = 0; i < app_argc; i++)
		_D("input argument %d : %s##", i, app_argv[i]);

	PERF("setup argument done");
	_E("lock up test log(no error) : setup argument done");

	/* Temporary log: launch time checking */
	LOG(LOG_DEBUG, "LAUNCH", "[%s:Platform:launchpad:done]", app_path);

	__preload_exec(app_argc, app_argv);

	__normal_fork_exec(app_argc, app_argv);
}

_static_ void __add_history(int caller, int callee, const char *pkgname, 
				bundle *b, const char *app_path)
{
	struct history_data *hd;
	bundle_raw *kb_data;
	int len;

	_D("***** HISTORY *****\n");
	_D("%d ==> %d(%s) \n", caller, callee, pkgname);
	_D("*******************\n");

	if (b) {
		bundle_encode(b, (bundle_raw **)&kb_data, &len);
		hd = (struct history_data *)malloc(sizeof(char) * (len+1029));

		strncpy(hd->pkg_name, pkgname, MAX_PACKAGE_STR_SIZE-1);
		strncpy(hd->app_path, app_path, MAX_PACKAGE_APP_PATH_SIZE-1);
		hd->len = len;
		memcpy(hd->data, kb_data, len);

		__app_send_raw(AUL_UTIL_PID, APP_ADD_HISTORY, (unsigned char *)hd,
			hd->len+1029);
		free(kb_data);
		free(hd);
	} else {
		hd = (struct history_data *)malloc(sizeof(char) * 1029);

		strncpy(hd->pkg_name, pkgname, MAX_PACKAGE_STR_SIZE-1);
		strncpy(hd->app_path, app_path, MAX_PACKAGE_APP_PATH_SIZE-1);
		hd->len = 0;

		__app_send_raw(AUL_UTIL_PID, APP_ADD_HISTORY, (unsigned char *)hd,
			1029);
		free(hd);
	}

	return;
}


/*
 * Parsing original app path to retrieve default bundle
 *
 * -1 : Invalid sequence
 * -2 : Buffer overflow
 *
 */
static inline int __parser(const char *arg, char *out, int out_size)
{
	register int i;
	int state = 1;
	char *start_out = out;

	if (arg == NULL || out == NULL) {
		/* Handles null buffer*/
		return 0;
	}

	for (i = 0; out_size > 1; i++) {
		switch (state) {
		case 1:
			switch (arg[i]) {
			case ' ':
			case '\t':
				state = 5;
				break;
			case '\0':
				state = 7;
				break;
			case '\"':
				state = 2;
				break;
			case '\\':
				state = 4;
				break;
			default:
				*out = arg[i];
				out++;
				out_size--;
				break;
			}
			break;
		case 2:	/* escape start*/
			switch (arg[i]) {
			case '\0':
				state = 6;
				break;
			case '\"':
				state = 1;
				break;
			default:
				*out = arg[i];
				out++;
				out_size--;
				break;
			}
			break;
		case 4:	/* character escape*/
			if (arg[i] == '\0') {
				state = 6;
			} else {
				*out = arg[i];
				out++;
				out_size--;
				state = 1;
			}
			break;
		case 5:	/* token*/
			if (out != start_out) {
				*out = '\0';
				out_size--;
				return i;
			}
			i--;
			state = 1;
			break;
		case 6:
			return -1;	/* error*/
		case 7:	/* terminate*/
			*out = '\0';
			out_size--;
			return 0;
		default:
			state = 6;
			break;	/* error*/
		}
	}

	if (out_size == 1) {
		*out = '\0';
	}
	/* Buffer overflow*/
	return -2;
}

_static_ void __modify_bundle(bundle * kb, int caller_pid,
			    app_info_from_db * menu_info, int cmd)
{
	char tmp_pid[MAX_PID_STR_BUFSZ];

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", caller_pid);
	bundle_add(kb, AUL_K_CALLER_PID, tmp_pid);
	bundle_del(kb, AUL_K_PKG_NAME);
	if (cmd == APP_START_RES)
		bundle_add(kb, AUL_K_WAIT_RESULT, "1");

	/* Parse app_path to retrieve default bundle*/
	if (cmd == APP_START || cmd == APP_START_RES || cmd == APP_OPEN || cmd == APP_RESUME) {
		char *ptr;
		char exe[MAX_PATH_LEN];
		int flag;

		ptr = _get_original_app_path(menu_info);

		flag = __parser(ptr, exe, sizeof(exe));
		if (flag > 0) {
			char key[256];
			char value[256];

			ptr += flag;
			_D("parsing app_path: EXEC - %s\n", exe);

			do {
				flag = __parser(ptr, key, sizeof(key));
				if (flag <= 0)
					break;
				ptr += flag;

				flag = __parser(ptr, value, sizeof(value));
				if (flag < 0)
					break;
				ptr += flag;

				/*bundle_del(kb, key);*/
				bundle_add(kb, key, value);
			} while (flag > 0);
		} else if (flag == 0) {
			_D("parsing app_path: No arguments\n");
		} else {
			_D("parsing app_path: Invalid argument\n");
		}
	}
}

_static_ int __child_raise_win_by_x(int pid, void *priv)
{
	return x_util_raise_win(pid);
}

_static_ int __raise_win_by_x(int pid)
{
	int pgid;
	if (x_util_raise_win(pid) == 0)
		return 0;

	/* support app launched by shell script*/
	pgid = getpgid(pid);
	_D("X raise failed. try to find first child & raise it - c:%d p:%d\n",
	   pgid, pid);

	if (pgid <= 1)
		return -1;
	if (__proc_iter_pgid(pgid, __child_raise_win_by_x, NULL) < 0)
		return -1;

	return 0;
}

_static_ int __send_to_sigkill(int pid)
{
	int pgid;

	pgid = getpgid(pid);
	if (pgid <= 1)
		return -1;

	if (killpg(pgid, SIGKILL) < 0)
		return -1;

	return 0;
}

_static_ int __term_app(int pid)
{
	int dummy;
	if (__app_send_raw
	    (pid, APP_TERM_BY_PID, (unsigned char *)&dummy, sizeof(int)) < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (__send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			return -1;
		}
	}
	_D("term done\n");
	return 0;
}

_static_ int __resume_app(int pid)
{
	int dummy;
	int ret;
	if ((ret =
	     __app_send_raw(pid, APP_RESUME_BY_PID, (unsigned char *)&dummy,
			    sizeof(int))) < 0) {
		if (ret == -EAGAIN)
			_E("resume packet timeout error");
		else {
			_D("resume packet send error - use raise win");
			if (__raise_win_by_x(pid) < 0) {
				_E("raise failed - %d resume fail\n", pid);
				_E("we will term the app - %d\n", pid);
				__send_to_sigkill(pid);
				ret = -1;
			} else
				ret = 0;
		}
	}
	_D("resume done\n");
	return ret;
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if(pid_str)
		goto end;

	pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (pid_str == NULL)
		return -1;

end:
	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
}

_static_ int __foward_cmd(int cmd, bundle *kb, int cr_pid)
{
	int pid;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	int datalen;
	bundle_raw *kb_data;
	int res;

	if ((pid = __get_caller_pid(kb)) < 0)
			return AUL_R_ERROR;

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", cr_pid);

	bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);

	bundle_encode(kb, &kb_data, &datalen);
	if ((res = __app_send_raw(pid, cmd, kb_data, datalen)) < 0)
		res = AUL_R_ERROR;

	free(kb_data);

	return res;
}

_static_ int __app_process_by_pid(int cmd, 
	const char *pkg_name, struct ucred *cr)
{
	int pid;
	int ret = -1;

	if (pkg_name == NULL)
		return -1;

	if ((cr->uid != 0) && (cr->uid != INHOUSE_UID)) {
		_E("reject by security rule, your uid is %u\n", cr->uid);
		return -1;
	}

	pid = atoi(pkg_name);
	if (pid <= 1) {
		_E("invalid pid");
		return -1;
	}

	switch (cmd) {
	case APP_RESUME_BY_PID:
		ret = __resume_app(pid);
		break;
	case APP_TERM_BY_PID:
		ret = __term_app(pid);
		break;
	case APP_KILL_BY_PID:
		if ((ret = __send_to_sigkill(pid)) < 0)
			_E("fail to killing - %d\n", pid);
	}

	return ret;
}

_static_ int __nofork_processing(int cmd, int pid, bundle * kb)
{
	int ret = -1;
	switch (cmd) {
	case APP_OPEN:
	case APP_RESUME:
		_D("resume app's pid : %d\n", pid);
		if ((ret = __resume_app(pid)) < 0)
			_E("__resume_app failed. error code = %d", ret);
		PERF("resume app done");
		break;

	case APP_START:
	case APP_START_RES:
		_D("fake launch pid : %d\n", pid);
		if ((ret = __fake_launch_app(cmd, pid, kb)) < 0)
			_E("fake_launch failed. error code = %d", ret);
		PERF("fake launch done");
		break;
	}
	return ret;
}

_static_ void __real_send(int clifd, int ret)
{
	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
		}
		_E("send fail to client");
	}

	close(clifd);
}

_static_ void __send_result_to_caller(int clifd, int ret)
{
	char *cmdline;
	int wait_count;
	int cmdline_changed = 0;
	int cmdline_exist = 0;

	if (clifd == -1)
		return;

	if (ret <= 1) {
		__real_send(clifd, ret);
		return;
	}
	/* check normally was launched?*/
	wait_count = 1;
	do {
		cmdline = __proc_get_cmdline_bypid(ret);
		if (cmdline == NULL) {
			_E("error founded when being launched with %d", ret);

		} else if (strcmp(cmdline, launchpad_cmdline)) {
			free(cmdline);
			cmdline_changed = 1;
			break;
		} else {
			cmdline_exist = 1;
			free(cmdline);
		}

		_D("-- now wait to change cmdline --");
		usleep(50 * 1000);	/* 50ms sleep*/
		wait_count++;
	} while (wait_count <= 20);	/* max 50*20ms will be sleep*/

	if ((!cmdline_exist) && (!cmdline_changed)) {
		__real_send(clifd, -1);	/* abnormally launched*/
		return;
	}

	if (!cmdline_changed)
		_E("process launched, but cmdline not changed");

	__real_send(clifd, ret);
	return;
}

_static_ void __launchpad_main_loop(int main_fd)
{
	bundle *kb = NULL;
	app_pkt_t *pkt = NULL;
	app_info_from_db *menu_info = NULL;

	const char *pkg_name = NULL;
	const char *app_path = NULL;
	int pid = -1;
	int clifd = -1;
	struct ucred cr;
	int is_real_launch = 0;

	char sock_path[UNIX_PATH_MAX] = {0,};

	pkt = __app_recv_raw(main_fd, &clifd, &cr);
	if (!pkt) {
		_D("packet is NULL");
		goto end;
	}

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_D("bundle decode error");
		goto end;
	}

	INIT_PERF(kb);
	PERF("packet processing start");

	if (pkt->cmd == APP_RESULT || pkt->cmd == APP_CANCEL) {
		pid = __foward_cmd(pkt->cmd, kb, cr.pid);
		goto end;
	}

	pkg_name = bundle_get_val(kb, AUL_K_PKG_NAME);
	_D("pkg name : %s\n", pkg_name);

	if (pkt->cmd == APP_TERM_BY_PID || pkt->cmd == APP_RESUME_BY_PID ||
	    pkt->cmd == APP_KILL_BY_PID) {
		pid = __app_process_by_pid(pkt->cmd, pkg_name, &cr);
		goto end;
	}

	menu_info = _get_app_info_from_db_by_pkgname(pkg_name);
	if (menu_info == NULL) {
		_D("such pkg no found");
		goto end;
	}

	app_path = _get_app_path(menu_info);
	if(app_path == NULL) {
		_E("app_path is NULL");
		goto end;
	}
	if (app_path[0] != '/') {
		_D("app_path is not absolute path");
		goto end;
	}

	__modify_bundle(kb, cr.pid, menu_info, pkt->cmd);
	pkg_name = _get_pkgname(menu_info);

	PERF("get package information & modify bundle done");

	if (_is_app_multi_inst(menu_info) == 0)
		pid = __proc_iter_cmdline(NULL, (void *)app_path);

	PERF("find pid by searching proc file system done");

	if (pid > 0) {
		int ret;

		if (cr.pid == pid) {
			_D("caller process & callee process is same.[%s:%d]",
			   pkg_name, pid);
			pid = -ELOCALLAUNCH_ID;
		} else if ((ret = __nofork_processing(pkt->cmd, pid, kb)) < 0)
			pid = ret;
	} else if (pkt->cmd != APP_RESUME) {
		pid = fork();
		if (pid == 0) {
			PERF("fork done");
			_E("lock up test log(no error) : fork done");

			close(clifd);
			close(main_fd);
			ail_db_close();
			__signal_unset_sigchld();
			__signal_fini();

			snprintf(sock_path, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, getpid());
			unlink(sock_path);

			PERF("prepare exec - first done");
			_E("lock up test log(no error) : prepare exec - first done");

			if (__prepare_exec(pkg_name, app_path,
					   menu_info, kb) < 0) {
				_E("preparing work fail to launch - "
				   "can not launch %s\n", pkg_name);
				exit(-1);
			}

			PERF("prepare exec - second done");
			_E("lock up test log(no error) : prepare exec - second done");

			__real_launch(app_path, kb);

			exit(-1);
		}
		_D("==> real launch pid : %d %s\n", pid, app_path);
		is_real_launch = 1;
	}

 end:
	__send_result_to_caller(clifd, pid);

	if (pid > 0) {
		int ret;
		ret = ac_check_launch_privilege(pkg_name, menu_info->pkg_type, pid);
		_D("ac_check_launch_privilege : %d", ret);
		switch (pkt->cmd) {
		case APP_OPEN:
		case APP_RESUME:
			__add_history(cr.pid, pid, pkg_name, NULL, app_path);
			break;
		case APP_START:
		case APP_START_RES:
			__add_history(cr.pid, pid, pkg_name, kb, app_path);
			break;
		default:
			_D("no launch case");
		}
		if (is_real_launch) {
			/*TODO: retry*/
			__signal_block_sigchld();
			__send_app_launch_signal(pid);
			__signal_unblock_sigchld();
		}
	}

	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);

	if (kb != NULL)
		bundle_free(kb);
	if (pkt != NULL)
		free(pkt);

	/* Active Flusing for Daemon */
	if (initialized > AUL_POLL_CNT) {
		sqlite3_release_memory(SQLITE_FLUSH_MAX);
		malloc_trim(0);
		initialized = 1;
	}

}

_static_ int __launchpad_pre_init(int argc, char **argv)
{
	int fd;

	/* signal init*/
	__signal_init();

	/* dac init*/
	__dac_init();

	/* get my(launchpad) command line*/
	launchpad_cmdline = __proc_get_cmdline_bypid(getpid());
	if (launchpad_cmdline == NULL) {
		_E("launchpad cmdline fail to get");
		return -1;
	}
	_D("launchpad cmdline = %s", launchpad_cmdline);

	/* create launchpad sock        */
	fd = __create_server_sock(LAUNCHPAD_PID);
	if (fd < 0) {
		_E("server sock error");
		return -1;
	}

	__preload_init(argc, argv);

	__preexec_init(argc, argv);

	return fd;
}

_static_ int __launchpad_post_init()
{
	/* Setting this as a global variable to keep track 
	of launchpad poll cnt */
	/* static int initialized = 0;*/

	if (initialized) {
		initialized++;
		return 0;
	}

	if (__signal_set_sigchld() < 0)
		return -1;

	initialized++;

	return 0;
}

int main(int argc, char **argv)
{
	int main_fd;
	struct pollfd pfds[POLLFD_MAX];
	int i;

	/* init without concerning X & EFL*/
	main_fd = __launchpad_pre_init(argc, argv);
	if (main_fd < 0) {
		_E("launchpad pre init failed");
		exit(-1);
	}

	pfds[0].fd = main_fd;
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;

	while (1) {
		if (poll(pfds, POLLFD_MAX, -1) < 0)
			continue;

		/* init with concerning X & EFL (because of booting 
		sequence problem)*/
		if (__launchpad_post_init() < 0) {
			_E("launcpad post init failed");
			exit(-1);
		}

		for (i = 0; i < POLLFD_MAX; i++) {
			if ((pfds[i].revents & POLLIN) != 0) {
				__launchpad_main_loop(pfds[i].fd);
			}
		}
	}
}

