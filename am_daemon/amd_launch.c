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

#include <signal.h>
#include <Ecore_X.h>
#include <Ecore_Input.h>
#include <utilX.h>
#include <Ecore.h>
#include <Evas.h>
#include <Ecore_Evas.h>

#include <bundle.h>
#include <aul.h>
#include <glib.h>
#ifdef _APPFW_FEATURE_APP_CHECKER
#include <app-checker-server.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <pkgmgr-info.h>
#include <vconf.h>
#include <proc_stat.h>
#include <poll.h>

#include "amd_config.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_key.h"
#include "app_sock.h"
#include "simple_util.h"
#include "amd_cgutil.h"
#include "launch.h"
#include "app_signal.h"

#define DAC_ACTIVATE

#include "access_control.h"


#define TERM_WAIT_SEC 3
#define INIT_PID 1

#define AUL_PR_NAME			16
#define PATH_APP_ROOT "/opt/usr/apps"
#define PATH_DATA "/data"
#define SDK_CODE_COVERAGE "CODE_COVERAGE"
#define SDK_DYNAMIC_ANALYSIS "DYNAMIC_ANALYSIS"
#define PATH_DA_SO "/home/developer/sdk_tools/da/da_probe.so"

#define PHONE_ORIENTATION_MODE "memory/private/sensor/10001"
#define AMD_EFFECT_IMAGE_ENABLE "db/setting/effect_image"
#define PHONE_ROTATE_LOCK "db/setting/auto_rotate_screen"

#define SYS_MIN_CPU_LOCK_FILE "/sys/devices/system/cpu/cpufreq/slp/min_cpu_lock"
#define MIN_CPU_LCK_CNT 0
#define MAX_CPU_LCK_CNT 2

#define HIDE_INDICATOR 0
#define SHOW_INDICATOR 1

#ifdef _APPFW_FEATURE_CPU_BOOST
#define APP_BOOSTING_PERIOD 1500 //msec
#endif

static char *amd_cmdline;

struct appinfomgr *_laf;
struct cginfo *_lcg;

DBusConnection *conn;
guint grab_timer_id;


#if 0
/*Unused data structure. Will be removed*/
typedef struct {
	char *pkg_name;		/* package */
	char *app_path;		/* exec */
	char *original_app_path;	/* exec */
	int multiple;		/* x_slp_multiple */
	char *pkg_type;
} app_info_from_pkgmgr;
#endif

static GList *_kill_list;

struct ktimer {
	pid_t pid;
	char *group;
	guint tid; /* timer ID */
	struct cginfo *cg;
};

static const char *atom_name = "_E_COMP_FAKE_LAUNCH_IMAGE"; // Atomic ID string
static Ecore_X_Atom ATOM_IMAGE_EFFECT; //Atomic ID
static void __amd_effect_image_file_set(char *image_file);
static void __amd_send_message_to_e17(int screenmode, const char * indicator, int effect_type, int theme);
static int __amd_change_min_cpulock_count(int value);
static Eina_Bool __amd_restore_min_cpulock_count_cb(void *data);
static void __set_reply_handler(int fd, int pid, int clifd, int cmd);
static void __real_send(int clifd, int ret);

static void _set_sdk_env(const char* appid, char* str) {
	char buf[MAX_LOCAL_BUFSZ];
	int ret;

	_D("key : %s / value : %s", AUL_K_SDK, str);
	/* http://gcc.gnu.org/onlinedocs/gcc/Cross_002dprofiling.html*/
	/* GCOV_PREFIX contains the prefix to add to the absolute paths in the object file. */
	/*		Prefix can be absolute, or relative. The default is no prefix.  */
	/* GCOV_PREFIX_STRIP indicates the how many initial directory names */
	/*		to stripoff the hardwired absolute paths. Default value is 0. */
	if (strncmp(str, SDK_CODE_COVERAGE, strlen(str)) == 0) {
		snprintf(buf, MAX_LOCAL_BUFSZ, PATH_APP_ROOT"/%s"PATH_DATA, appid);
		ret = setenv("GCOV_PREFIX", buf, 1);
		_D("GCOV_PREFIX : %d", ret);
		ret = setenv("GCOV_PREFIX_STRIP", "4096", 1);
		_D("GCOV_PREFIX_STRIP : %d", ret);
	} else if (strncmp(str, SDK_DYNAMIC_ANALYSIS, strlen(str)) == 0) {
		ret = setenv("LD_PRELOAD", PATH_DA_SO, 1);
		_D("LD_PRELOAD : %d", ret);
	}
}

#define USE_ENGINE(engine) setenv("ELM_ENGINE", engine, 1);

static void _set_env(const char *appid, bundle * kb, const char *hwacc)
{
	const char *str;
	const char **str_array;
	int len;
	int i;

	setenv("PKG_NAME", appid, 1);

	USE_ENGINE("gl")

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str != NULL)
		setenv("APP_START_TIME", str, 1);

	if(bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
		if(str_array != NULL) {
			for (i = 0; i < len; i++) {
				_D("index : [%d]", i);
				_set_sdk_env(appid, (char *)str_array[i]);
			}
		}
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if(str != NULL) {
			_set_sdk_env(appid, (char *)str);
		}
	}
	if (hwacc != NULL)
		setenv("HWACC", hwacc, 1);
}

static void _prepare_exec(const char *appid, bundle *kb)
{
	const struct appinfo *ai;
	const char *app_path = NULL;
	const char *pkg_type = NULL;
	char *file_name;
	char process_name[AUL_PR_NAME];
	const char *hwacc;
	int ret;

	setsid();

	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);

	ai = appinfo_find(_laf, appid);

	app_path = appinfo_get_value(ai, AIT_EXEC);
	pkg_type = appinfo_get_value(ai, AIT_TYPE);
	hwacc = appinfo_get_value(ai, AIT_HWACC);

	/* SET PRIVILEGES*/
	 _D("appid : %s / pkg_type : %s / app_path : %s ", appid, pkg_type, app_path);
	if (pkg_type && strncmp(pkg_type, "wgt", 3) !=0 && (ret = __set_access(appid, pkg_type, app_path)) < 0) {
		 _D("fail to set privileges - check your package's credential : %d\n", ret);
		return;
	}

	/* SET DUMPABLE - for coredump*/
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME*/
	if (app_path == NULL) {
		_D("app_path should not be NULL - check menu db");
		return;
	}
	file_name = strrchr(app_path, '/') + 1;
	if (file_name == NULL) {
		_D("can't locate file name to execute");
		return;
	}
	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	/* SET ENVIROMENT*/
	_set_env(appid, kb, hwacc);
}

static int _add_cgroup(struct cginfo *cg, const char *group, int pid)
{
	int r;

	r = cgutil_exist_group(cg, CTRL_MGR, group);
	if (r == -1) {
		_E("exist check error: %s", strerror(errno));
		return -1;
	}

	if (r == 0) { /* not exist */
		r = cgutil_create_group(cg, CTRL_MGR, group);
		if (r == -1) {
			_E("create group error");
			return -1;
		}
	}

	r = cgutil_group_add_pid(cg, CTRL_MGR, group, pid);
	if (r == -1) {
		_E("add pid to group error");
		cgutil_remove_group(cg, CTRL_MGR, group);
		return -1;
	}

	return 0;
}

static char **__create_argc_argv(bundle * kb, int *margc)
{
	char **argv;
	int argc;

	argc = bundle_export_to_argv(kb, &argv);

	*margc = argc;
	return argv;
}
static void _do_exec(struct cginfo *cg, const char *cmd, const char *group, bundle *kb)
{
	gchar **argv;
	gint argc;
	char **b_argv;
	int b_argc;
	gboolean b;
	int r;

	r = _add_cgroup(cg, group, getpid());
	if (r == -1)
		return;

	b = g_shell_parse_argv(cmd, &argc, &argv, NULL);

	if (kb) {
		b_argv = __create_argc_argv(kb, &b_argc);
		b_argv[0] = strdup(argv[0]);
		_prepare_exec(group, kb);
		execv(b_argv[0], b_argv);
	}

	if (b) {
		_prepare_exec(group, kb);
		execv(argv[0], argv);
	}

	_E("exec error: %s", strerror(errno));
	g_strfreev(argv);
}

static inline int __send_app_launch_signal(int launch_pid)
{
	DBusMessage *message;

	if (conn == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
					  AUL_DBUS_SIGNAL_INTERFACE,
					  AUL_DBUS_APPLAUNCH_SIGNAL);

	if (dbus_message_append_args(message,
				     DBUS_TYPE_UINT32, &launch_pid,
				     DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(conn, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(conn);
	dbus_message_unref(message);

	_D("send launch signal done\n");

	return 0;
}

static int __send_watchdog_signal(int pid, int signal_num)
{
	DBusMessage *message;

	if (conn == NULL)
		return -1;

	if (!_get_platform_ready()) {
		_E("[Info]_get_platform_ready return false");
		return -1;
	}

	if(_status_get_cooldown_status() == COOLDOWN_LIMIT) {
		_E("[Info]cooldown status : LimitAction");
		return -1;
	}

	message = dbus_message_new_signal(RESOURCED_PROC_OBJECT,
					  RESOURCED_PROC_INTERFACE,
					  RESOURCED_PROC_WATCHDOG_SIGNAL);

	if (dbus_message_append_args(message,
				     DBUS_TYPE_INT32, &pid,
				     DBUS_TYPE_INT32, &signal_num,
				     DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(conn, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(conn);
	dbus_message_unref(message);

	_D("send launch signal done\n");

	return 0;
}

static int __check_cmdline(int ret)
{
	char *cmdline;
	int wait_count;
	int cmdline_changed = 0;
	int cmdline_exist = 0;
	int r;

	if (ret <= 1)
		return -1;

	/* check normally was launched?*/
	wait_count = 1;
	do {
		cmdline = __proc_get_cmdline_bypid(ret);
		if (cmdline == NULL) {
			_E("error founded when being launched with %d", ret);

		} else if (strcmp(cmdline, amd_cmdline)) {
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
		return -1;
	}

	if (!cmdline_changed)
		_E("process launched, but cmdline not changed");

	return ret;
}

int service_start(struct cginfo *cg, const char *group, const char *cmd, bundle *kb)
{
	int r;
	pid_t p;

	if (!cg || !group || !*group || !cmd || !*cmd) {
		errno = EINVAL;
		_E("service start: %s", strerror(errno));
		return -1;
	}

	p = fork();
	switch (p) {
	case 0: /* child process */
		_D("start service");
#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
		r = setpriority(PRIO_PROCESS, 0, 0);
		if (r == -1)
		{
			SECURE_LOGE("Setting process (%d) priority to 0 failed, errno: %d (%s)",
					getpid(), errno, strerror(errno));
		}
#endif
		_do_exec(cg, cmd, group, kb);
		/* exec error */

		exit(0);
		break;
	case -1:
		_E("service start: fork: %s", strerror(errno));
		r = -1;
		break;
	default: /* parent process */
		_D("child process: %d", p);
		r = __check_cmdline(p);
		if(r > 0)
			__send_app_launch_signal(r);
		break;
	}

	return r;
}

int _start_srv(const struct appinfo *ai, bundle *kb)
{
	int r;
	const char *group;
	const char *cmd;
	const char *pkgid;

	group = appinfo_get_filename(ai);

	cmd = appinfo_get_value(ai, AIT_EXEC);
	if (!cmd) {
		_E("start service: '%s' has no exec", group);
		return -1;
	}

	r = service_start(_lcg, group, cmd, kb);
	if (r == -1) {
		_E("start service: '%s': failed", group);
		return -1;
	}

	pkgid = appinfo_get_value(ai, AIT_PKGID);
	proc_cgroup_launch(PROC_CGROUP_SET_SERVICE_REQUEST, r, group, pkgid);
	_status_add_app_info_list(group, cmd, NULL, r, -1);

	return 0;
}

static void _free_kt(struct ktimer *kt)
{
	if (!kt)
		return;

	cgutil_unref(&kt->cg);
	free(kt->group);
	free(kt);
}

static void _kill_pid(struct cginfo *cg, const char *group, pid_t pid)
{
	int r;

	if (pid <= INIT_PID) /* block sending to all process or init */
		return;

	r = cgutil_exist_group(cg, CTRL_MGR, group);
	if (r == -1) {
		_E("send SIGKILL: exist: %s", strerror(errno));
		return;
	}
	if (r == 0) {
		_D("send SIGKILL: '%s' not exist", group);
		return;
	}

	/* TODO: check pid exist in group */

	r = kill(pid, 0);
	if (r == -1) {
		_D("send SIGKILL: pid %d not exist", pid);
		return;
	}

	r = kill(pid, SIGKILL);
	if (r == -1)
		_E("send SIGKILL: %s", strerror(errno));
}

static gboolean _ktimer_cb(gpointer data)
{
	struct ktimer *kt = data;

	_kill_pid(kt->cg, kt->group, kt->pid);
	_kill_list = g_list_remove(_kill_list, kt);
	_free_kt(kt);

	return FALSE;
}

static void _add_list(struct cginfo *cg, const char *group, pid_t pid)
{
	struct ktimer *kt;

	kt = calloc(1, sizeof(*kt));
	if (!kt)
		return;

	kt->pid = pid;
	kt->group = strdup(group);
	if (!kt->group) {
		free(kt);
		return;
	}

	kt->cg = cgutil_ref(cg);
	kt->tid = g_timeout_add_seconds(TERM_WAIT_SEC, _ktimer_cb, kt);

	_kill_list = g_list_append(_kill_list, kt);
}

static inline void _del_list(GList *l)
{
	struct ktimer *kt;

	if (!l)
		return;

	kt = l->data;

	g_source_remove(kt->tid);
	_free_kt(kt);
	_kill_list = g_list_delete_link(_kill_list, l);
}

static int _kill_pid_cb(void *user_data, const char *group, pid_t pid)
{
	int r;

	if (pid <= INIT_PID) /* block sending to all process or init */
		return 0;

	r = kill(pid, SIGTERM);
	if (r == -1)
		_E("send SIGTERM: %s", strerror(errno));

	_add_list(user_data, group, pid);

	return 0;
}

int service_stop(struct cginfo *cg, const char *group)
{
	if (!cg || !group || !*group) {
		errno = EINVAL;
		return -1;
	}

	_D("service_stop, group %s", group);

	return cgutil_group_foreach_pid(cg, CTRL_MGR, FILENAME(group),
			_kill_pid_cb, cg);
}

void service_release(const char *group)
{
	GList *l;
	GList *d;

	if (!group || !*group)
		return;

	group = FILENAME(group);

	d = NULL;
	for (l = _kill_list; l; l = g_list_next(l)) {
		struct ktimer *k = l->data;

		_del_list(d);

		if (k->group && !strcmp(k->group, group))
			d = l;
		else
			d = NULL;
	}

	_del_list(d);
}

int _send_to_sigkill(int pid)
{
	int pgid;

	pgid = getpgid(pid);
	if (pgid <= 1)
		return -1;

	if (killpg(pgid, SIGKILL) < 0)
		return -1;

	return 0;
}
int _resume_app(int pid, int clifd)
{
	int dummy;
	int ret;
	if ((ret =
	     __app_send_raw_with_delay_reply(pid, APP_RESUME_BY_PID, (unsigned char *)&dummy,
			    sizeof(int))) < 0) {
		if (ret == -EAGAIN)
			_E("resume packet timeout error");
		else {
			_E("raise failed - %d resume fail\n", pid);
			_E("we will term the app - %d\n", pid);
			_send_to_sigkill(pid);
			ret = -1;
		}
		__real_send(clifd, ret);
	}
	_D("resume done\n");

	if (ret > 0)
		__set_reply_handler(ret, pid, clifd, APP_RESUME_BY_PID);

	return ret;
}

int _fake_launch_app(int cmd, int pid, bundle * kb, int clifd)
{
	int datalen;
	int ret;
	bundle_raw *kb_data;

	bundle_encode(kb, &kb_data, &datalen);
	if ((ret = __app_send_raw_with_delay_reply(pid, cmd, kb_data, datalen)) < 0) {
		_E("error request fake launch - error code = %d", ret);
		__real_send(clifd, ret);
	}
	free(kb_data);

	if (ret > 0)
		__set_reply_handler(ret, pid, clifd, cmd);

	return ret;
}

static void __real_send(int clifd, int ret)
{
	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
		}
		_E("send fail to client");
	}

	close(clifd);
}

static gboolean __au_glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		if ((tmp->revents & (POLLIN | POLLPRI)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __au_glib_dispatch(GSource *src, GSourceFunc callback,
		gpointer data)
{
	callback(data);
	return TRUE;
}

static gboolean __au_glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	.prepare = __au_glib_prepare,
	.check = __au_glib_check,
	.dispatch = __au_glib_dispatch,
	.finalize = NULL
};

struct reply_info {
	GSource *src;
	GPollFD *gpollfd;
	guint timer_id;
	int clifd;
	int pid;
	int cmd;
};

static gboolean __reply_handler(gpointer data)
{
	struct reply_info *r_info = (struct reply_info *) data;;
	int fd = r_info->gpollfd->fd;
	int len;
	int res = 0;
	int clifd = r_info->clifd;
	int pid = r_info->pid;
	int cmd = r_info->cmd;

	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout : %s", strerror(errno));
			res = -EAGAIN;
		} else {
			_E("recv error : %s", strerror(errno));
			res = -ECOMM;
		}
	}
	close(fd);

	if(res < 0) {
		if ( cmd == APP_TERM_BY_PID ) {
			__real_send(clifd, -1);
		} else if ( cmd == APP_START_ASYNC ) {
			close(clifd);
		} else {
			__real_send(clifd, res);
		}
	} else {
		if ( cmd == APP_TERM_BY_PID ) {
			__real_send(clifd, 0);
		} else if ( cmd == APP_START_ASYNC ) {
			close(clifd);
		} else {
			__real_send(clifd, pid);
		}
	}

	_D("listen fd(%d) , send fd(%d), pid(%d), cmd(%d)", fd, clifd, pid, cmd);

	g_source_remove(r_info->timer_id);
	g_source_remove_poll(r_info->src, r_info->gpollfd);
	g_source_destroy(r_info->src);
	g_free(r_info->gpollfd);
	free(r_info);

	return TRUE;
}

static gboolean __recv_timeout_handler(gpointer data)
{
	struct reply_info *r_info = (struct reply_info *) data;
	int fd = r_info->gpollfd->fd;
	int ret = -EAGAIN;

	_E("application is not responding : pid(%d) cmd(%d)", r_info->pid, r_info->cmd);

	close(fd);

	switch (r_info->cmd) {
	case APP_OPEN:
	case APP_RESUME:
	case APP_START:
	case APP_START_RES:
	case APP_START_ASYNC:
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	case APP_START_MULTI_INSTANCE:
#endif
		__send_watchdog_signal(r_info->pid, SIGKILL);
		break;
	case APP_TERM_BY_PID:
		if (_send_to_sigkill(r_info->pid) < 0) {
			_E("fail to killing - %d\n", r_info->pid);
			__real_send(r_info->clifd, -1);
			return -1;
		} else {
			ret = 0;
		}
		break;
	}

	__real_send(r_info->clifd, ret);
	g_source_remove_poll(r_info->src, r_info->gpollfd);
	g_source_destroy(r_info->src);
	g_free(r_info->gpollfd);
	free(r_info);

	return FALSE;
}

static void __set_reply_handler(int fd, int pid, int clifd, int cmd)
{
	GPollFD *gpollfd;
	GSource *src;
	struct reply_info *r_info;

	src = g_source_new(&funcs, sizeof(GSource));

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	if (gpollfd == NULL) {
		_E("out of memory");
		g_source_unref(src);
		close(fd);
		close(clifd);
		return;
	}

	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	r_info = malloc(sizeof(*r_info));
	if (r_info == NULL) {
		_E("out of memory");
		g_free(gpollfd);
		g_source_unref(src);
		close(fd);
		close(clifd);
		return;
	}

	r_info->clifd = clifd;
	r_info->pid = pid;
	r_info->src = src;
	r_info->gpollfd = gpollfd;
	r_info->cmd = cmd;


	r_info->timer_id = g_timeout_add(5000, __recv_timeout_handler, (gpointer) r_info);
	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __reply_handler,
			(gpointer) r_info, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);
	g_source_attach(src, NULL);

	_D("listen fd : %d, send fd : %d", fd, clifd);
}

int _term_app(int pid, int clifd)
{
	int dummy;
	int ret;

	if ( (ret = __app_send_raw_with_delay_reply
	    (pid, APP_TERM_BY_PID, (unsigned char *)&dummy, sizeof(int))) < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			__real_send(clifd, -1);
			return -1;
		}
		__real_send(clifd, 0);
	}
	_D("term done\n");
	if (ret > 0)
		__set_reply_handler(ret, pid, clifd, APP_TERM_BY_PID);

	return 0;
}

#include <dirent.h>
#include <sqlite3.h>
static int __launchpad_update_task_managed_field(const char* app_id, int task_managed)
{
	sqlite3 *db = NULL;
	char *sqlite3_error_msg = NULL;

	if (sqlite3_open("/opt/dbspace/.pkgmgr_parser.db", &db) != SQLITE_OK) {
	    _E("sqlite3_open() failed! -> %s\n", sqlite3_errmsg(db));
	    return -1;
	}

	if (sqlite3_exec(db, "PRAGMA journal_mode = PERSIST", NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
	    _E("sqlite3_exec(\"PRAGMA journal_mode = PERSIST\") failed! -> %s", sqlite3_error_msg);
	    sqlite3_free(sqlite3_error_msg);
	    sqlite3_close(db);
	    return -1;
	}

	if (sqlite3_exec(db, "BEGIN EXCLUSIVE", NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
		_E("sqlite3_exec(\"BEGIN EXCLUSIVE\") failed! -> %s", sqlite3_error_msg);
	    sqlite3_free(sqlite3_error_msg);
		sqlite3_close(db);
		return -1;
	}

	char query[1024] = {0, };
	snprintf(query, 1024,"update package_app_info set app_taskmanage='%s' where app_id='%s'",
	        task_managed ? "true" : "false", app_id);

	if (sqlite3_exec(db, query, NULL, NULL, &sqlite3_error_msg) != SQLITE_OK) {
		_E("sqlite3_exec(\"%s\") failed! -> %s", query, sqlite3_error_msg);
		sqlite3_free(sqlite3_error_msg);
		return -1;
	}

	if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
		_E("sqlite3_exec(\"COMMIT\") failed!");
		if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
			_E("sqlite3_exec(\"ROLLBACK\") failed!");
		}
		sqlite3_close(db);
		return -1;
	}

	sqlite3_close(db);

return 0;
}

static void __pre_launching_processing(const char* app_id)
{
    const char* const PRE_LAUNCHING_LIST_DIR = "/opt/usr/etc/wrt_launchpad_daemon/pre_launching_list";

    struct stat file_status;
    if (stat(PRE_LAUNCHING_LIST_DIR, &file_status) == 0) {
        if (S_ISDIR(file_status.st_mode)) {
            int ret;
            DIR *dir = NULL;
            struct dirent entry, *result;

            dir = opendir(PRE_LAUNCHING_LIST_DIR);

            if (dir) {
                for (ret = readdir_r(dir, &entry, &result);
                     result != NULL && ret == 0;
                     ret = readdir_r(dir, &entry, &result)) {
                    if (strncmp(entry.d_name, ".", 2) == 0 ||
                        strncmp(entry.d_name, "..", 3) == 0) {
                        continue;
                    }

                    if (strcmp(entry.d_name, app_id) == 0)
                    {
                        __launchpad_update_task_managed_field(app_id, 1);
                    }
                }

                closedir(dir);
            }
            else {
                _E("opendir(\"%s\") failed!", PRE_LAUNCHING_LIST_DIR);
            }
        }
    }
}

static int __nofork_processing(int cmd, int pid, bundle * kb, int clifd)
{
	int ret = -1;
	int r;
	const char *operation;

	operation = bundle_get_val(kb, "__APP_SVC_OP_TYPE__");

#ifdef _APPFW_FEATURE_CPU_BOOST
	//TODO: CPU boosting for relaunching will be removed.
	//Home screen requests CPU boosting on launching or relaunching during 200 msec.
	if (cmd == APP_OPEN ||
			(operation != NULL && strncmp(operation, "http://tizen.org/appcontrol/operation/main", 512) == 0)) {
		char *arr[2];
		char val[32];
		snprintf(val, sizeof(val), "%d", APP_BOOSTING_PERIOD);
		arr[0] = val;
		arr[1] = NULL;
		ret = invoke_dbus_method_sync(SYSTEM_BUS_NAME, SYSTEM_OBJECT_PATH,
				SYSTEM_INTERFACE_NAME, SYSTEM_METHOD_NAME, "i", arr);
		_D("%s-%s : %d", SYSTEM_INTERFACE_NAME, SYSTEM_METHOD_NAME, ret);
	}
#endif
	_D("__nofork_processing, cmd: %d, pid: %d", cmd, pid);
	switch (cmd) {
	case APP_OPEN:
	case APP_RESUME:
		_D("resume app's pid : %d\n", pid);
		if ((ret = _resume_app(pid, clifd)) < 0)
			_E("__resume_app failed. error code = %d", ret);
		_D("resume app done");
		break;

	case APP_START:
	case APP_START_RES:
	case APP_START_ASYNC:
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	case APP_START_MULTI_INSTANCE:
#endif
		_D("fake launch pid : %d\n", pid);
		if ((ret = _fake_launch_app(cmd, pid, kb, clifd)) < 0)
			_E("fake_launch failed. error code = %d", ret);
		_D("fake launch done");
		break;
	}

	return ret;
}

#if __CPU_FREQ_CON
#include <sysman.h>
static Eina_Bool
__amd_sysman_restore_hz_timer_cb(void *data)
{
   struct context *ctxt = data;

   if (ctxt->timer)
     ctxt->timer = NULL;

   sysman_release_cpu_min_frequency ();

   _D("*******[1.6MHZ Support] Released\n " );

   return ECORE_CALLBACK_CANCEL; // same as EINA_FALSE
}
#endif

struct context{
	Ecore_Timer *timer;
};

static int __amd_change_min_cpulock_count(int value)
{
	int fd = -1;
	char buf[16]={0,};
	fd = open(SYS_MIN_CPU_LOCK_FILE, O_WRONLY);
	if (fd == -1)
		return -1;
	snprintf(buf, sizeof(buf), "%d", value);
	if (write(fd, buf, strlen(buf)) < 0) {
		_E("[AMD]: Unable to change min_cpu_lock value!, err: %s\n",strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	_D("[AMD]: Succesfully changed min cpu value to %d\n", value);
	return 0;
}

static Eina_Bool __amd_restore_min_cpulock_count_cb(void *data)
{
	struct context *ctxt = data;
	if (ctxt->timer)
		ctxt->timer = NULL;
	__amd_change_min_cpulock_count(MIN_CPU_LCK_CNT);
	return ECORE_CALLBACK_CANCEL;
}

static void __amd_effect_image_file_set(char *image_file)
{
	Ecore_X_Window root_win;
	root_win = ecore_x_window_root_first_get();
	SECURE_LOGD("path : %s", image_file);
	ecore_x_window_prop_string_set(root_win, ATOM_IMAGE_EFFECT,image_file);
}


static void __amd_send_message_to_e17(int screenmode, const char * indicator, int effect_type, int theme)
{
	Ecore_X_Window root_win;
	int ret;
	root_win = ecore_x_window_root_first_get();
	 _D("root win : %x",root_win);
	int screen_orientation[5]={0,0,270,180,90};
	if (screenmode > 4 || screenmode < 0)
		screenmode=0;

	if (strncmp(indicator, "true", 4) == 0){
		_D("[LAUNCHING EFFECT]: screen mode(%d), effect type(%d), theme(%d), indicator show",
			screen_orientation[screenmode], effect_type, theme);
		ret = ecore_x_client_message32_send (root_win, ATOM_IMAGE_EFFECT,
			ECORE_X_EVENT_MASK_WINDOW_PROPERTY, effect_type,
			screen_orientation[screenmode],
			SHOW_INDICATOR, theme, 0);

	}else{
		_D("[LAUNCHING EFFECT]: screen mode(%d), effect type(%d), theme(%d), indicator show",
			screen_orientation[screenmode], effect_type, theme);
		ret = ecore_x_client_message32_send (root_win, ATOM_IMAGE_EFFECT,
			ECORE_X_EVENT_MASK_WINDOW_PROPERTY, effect_type,
			screen_orientation[screenmode],
			HIDE_INDICATOR, theme, 0);
	}
	ecore_x_flush();
	_D("ecore_x_client_message32_send : %d",ret);
}



static int append_variant(DBusMessageIter *iter, const char *sig, char *param[])
{
	char *ch;
	int i;
	int int_type;
	uint64_t int64_type;

	if (!sig || !param)
		return 0;

	for (ch = (char*)sig, i = 0; *ch != '\0'; ++i, ++ch) {
		switch (*ch) {
		case 'i':
			int_type = atoi(param[i]);
			dbus_message_iter_append_basic(iter, DBUS_TYPE_INT32, &int_type);
			break;
		case 'u':
			int_type = atoi(param[i]);
			dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &int_type);
			break;
		case 't':
			int64_type = atoi(param[i]);
			dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT64, &int64_type);
			break;
		case 's':
			dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, param[i]);
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

int invoke_dbus_method_sync(const char *dest, const char *path,
		const char *interface, const char *method,
		const char *sig, char *param[])
{
	DBusMessage *msg;
	DBusMessageIter iter;
	DBusMessage *reply;
	DBusError err;
	int r, ret;

	msg = dbus_message_new_method_call(dest, path, interface, method);
	if (!msg) {
		_E("dbus_message_new_method_call(%s:%s-%s)", path, interface, method);
		return -EBADMSG;
	}

	if( param ) {
		dbus_message_iter_init_append(msg, &iter);
		r = append_variant(&iter, sig, param);
		if (r < 0) {
			_E("append_variant error(%d)", r);
			dbus_message_unref(msg);
			return -EBADMSG;
		}
	}

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, 500, &err);
	dbus_message_unref(msg);
	if (!reply) {
		_E("dbus_connection_send error(%s:%s)", err.name, err.message);
		dbus_error_free(&err);
		return -EBADMSG;
	}

	r = dbus_message_get_args(reply, &err, DBUS_TYPE_INT32, &ret, DBUS_TYPE_INVALID);
	dbus_message_unref(reply);
	if (!r) {
		_E("no message : [%s:%s]", err.name, err.message);
		dbus_error_free(&err);
		return -EBADMSG;
	}

	return ret;
}

static gboolean __grab_timeout_handler(gpointer data)
{
	int pid = (int) data;

	if(_input_window_get() != 0)
		ecore_x_pointer_ungrab();
	_D("pid(%d) ecore_x_pointer_ungrab", pid);

	return FALSE;
}

static bool __check_ug_client_process_pool(const char *app_path)
{
	char sympath[MAX_PACKAGE_APP_PATH_SIZE] = {0,};
	int ret;
	bool func_ret = true;

	if(!app_path) {
		_E("invalid input param");
		func_ret = false;
		goto func_out;
	}

	if(strncmp(app_path, "/usr/ug/bin/", strlen("/usr/ug/bin")) != 0) {
		func_ret = false;
		goto func_out;
	}

	if(readlink(app_path, sympath, MAX_PACKAGE_APP_PATH_SIZE-1) == -1) {
		_E("read app path link error(%d)", errno);
		func_ret = false;
		goto func_out;
	}

	if(strncmp(sympath, "/usr/bin/ug-client", strlen("/usr/bin/ug-client")) != 0) {
		func_ret = false;
	}

func_out :
	_D("ug process pool check result : %d", func_ret);
	return func_ret;
}

#ifdef _APPFW_FEATURE_MULTI_WINDOW
static void __add_multi_window_info(bundle* kb, const struct appinfo *ai, const char* callee_appid, const char* caller_appid)
{
	const struct appinfo *caller_ai;
	const struct appinfo *callee_ai;
	unsigned int layout = -1; // 0 : top of split window / 1 : bottom of split window
	const char *caller = NULL;
	Ecore_X_Window caller_win_id = 0;
	const char *bundle_layout = NULL;
	int is_open_via_multi = 0;
	int startup_type = 2; //2 means callee will be displayed as split view
	const char *caller_ai_multi_window = NULL;
	const char *callee_ai_multi_window = NULL;
	int ret = 0;
	int multiwindow_enabled = 0;

	/* check multi window is enabled or not */
	ret = vconf_get_bool(VCONFKEY_QUICKSETTING_MULTIWINDOW_ENABLED, &multiwindow_enabled);
	if((ret != VCONF_OK) || (multiwindow_enabled == 0)) {
		_D("multiwindow is disabled");
		return;
	}

	SECURE_LOGD("callee appid : %s / caller_appid : %s", callee_appid, caller_appid);

	/* check whether caller & callee ui app support multi window or not */
	caller_ai = appinfo_find(_laf, caller_appid);
	if(caller_ai == NULL) {
		_D("no caller appinfo");
		return;
	}
	caller_ai_multi_window = appinfo_get_value(caller_ai, AIT_MULTI_WINDOW);
	if((caller_ai_multi_window == NULL) || (strcmp(caller_ai_multi_window, "true") != 0)) {
		_D("caller app does not support multi window");
		return;
	}
	callee_ai = appinfo_find(_laf, callee_appid);
	if(callee_ai == NULL) {
		_D("no callee appinfo");
		return;
	}
	callee_ai_multi_window = appinfo_get_value(callee_ai, AIT_MULTI_WINDOW);
	if((callee_ai_multi_window == NULL) || (strcmp(callee_ai_multi_window, "true") != 0)) {
		_D("callee app does not support multi window");
		return;
	}

	/* check aul_forwad_app case */
	if((caller_appid) && (strcmp(caller_appid, "org.tizen.app-selector") == 0)) {
		_D("forward app case");
		return;
	}

	/* get multi window layout value */
	caller = bundle_get_val(kb, "__APP_SVC_K_WIN_ID__");
	if(caller) {
		caller_win_id = atoi(caller);
	} else {
		_D("caller win id is null");
		return;
	}
	if(caller_win_id == 0) {
		_D("caller id is 0");
		return;
	}

	if( ecore_x_window_prop_card32_get(caller_win_id,
		ECORE_X_ATOM_E_WINDOW_DESKTOP_LAYOUT, &layout, 1 ) != -1 )
	{
		if(layout == 0 || layout == 1) {
			_D("layout : %d", layout);
		} else {
			_W("x_window__prop_get layout value error : %d", layout);
			return;
		}
	} else {
		layout = -1;
	}

	do {
		const char *operation = NULL;
		operation = bundle_get_val(kb, "__APP_SVC_OP_TYPE__");
		if(operation == NULL) {
			_D("operation is null");
			break;
		}

		if(strcmp(operation,"http://tizen.org/appcontrol/operation/view") == 0) {
			int open_via_multi = 0;
			ret = vconf_get_bool(VCONFKEY_SETAPPL_OPEN_VIA_MULTI, &open_via_multi);
			_D("open_via_multi : %d", open_via_multi);
			if((ret == VCONF_OK) && (open_via_multi == 1)) {
				is_open_via_multi = 1;
				/* callee window should not be transient for caller window under "open in multi window" mode */
				if(caller) {
					if(bundle_del(kb, "__APP_SVC_K_WIN_ID__") == -1) {
						_D("failed to remove window id of bundle (errno : %d)", errno);
					}
				}
				break;
			}
		}
	} while (0);

	if(is_open_via_multi) {
		if(layout == 1)
			layout = 0;
		else
			layout = 1;

		_D("open via multi scenario. reverted layout id is %d", layout);
	} else {
		/* multi window support app need be launched with full view
		when app is launched from multi window support app with full view. */
		if(layout == -1) {
			startup_type = 0;
		}
	}

	char tmp_layout[128];
	char tmp_startup[128];

	snprintf(tmp_layout, 128, "%d", layout);
	snprintf(tmp_startup, 128, "%d", startup_type);

	if(bundle_add(kb, "window_layout_id", tmp_layout) != 0) {
		_W("winow layout id bundle add error");
	}
	if(bundle_add(kb, "window_startup_type", tmp_startup) != 0) {
		_W("winow startup type bundle add error");
	}

	SECURE_LOGD("window startup type(%d) and layout id(%d) is added", startup_type, layout);

	return;
}
#endif

int __check_mode(const struct appinfo *ai)
{
#ifdef _APPFW_FEATURE_TTS_MODE
	int tts_mode = 0;
	const char *tts_support = NULL;
#endif
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	int ups_mode = 0;
	const char *ups_support = NULL;
#endif

#ifdef _APPFW_FEATURE_TTS_MODE
	vconf_get_bool(VCONFKEY_SETAPPL_ACCESSIBILITY_TTS, &tts_mode);
	if(tts_mode) {
		tts_support = appinfo_get_value(ai, AIT_TTS);
		_D("tts : %d %s", tts_mode, tts_support);
		if(tts_support && strncmp(tts_support, "false", 5) == 0)
			return -1;
	}
#endif

#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	vconf_get_int(VCONFKEY_SETAPPL_PSMODE, &ups_mode);
	if(ups_mode == SETTING_PSMODE_WEARABLE) {
		ups_support = appinfo_get_value(ai, AIT_UPS);
		_D("ups : %d %s", ups_mode, ups_support);
		if(ups_support && strncmp(ups_support, "false", 5) == 0)
			return -1;
	}
#endif

	return 0;
}

int _start_app(char* appid, bundle* kb, int cmd, int caller_pid, uid_t caller_uid, int fd)
{
	const struct appinfo *ai;
	const struct appinfo *caller_ai;
	int ret = -1;
	const char *multiple = NULL;
	const char *app_path = NULL;
	const char *pkg_type = NULL;
	const char *component_type = NULL;
	int pid = -1;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	const char *permission;
	const char *pkgid;
	const char *preload;
	const char *pkg_status;
	const char *operation;
	const char *fake_effect;
	char caller_appid[256];
	char* caller = NULL;
	char* curr_caller = NULL;
	char* old_caller = NULL;
	pkgmgrinfo_cert_compare_result_type_e compare_result;
	int delay_reply = 0;
	int pad_pid = LAUNCHPAD_PID;
	int status = -1;
	int r = -1;
	char trm_buf[MAX_PACKAGE_STR_SIZE];

	int effect_mode = 0;
#ifdef _APPFW_FEATURE_WMS_CONNECTION_CHECK
	int wmanager_connected = 0;
#endif
	char *caller_component_type = NULL;

	if (appid == NULL || kb == NULL
		|| caller_pid < 0 || fd < 0) {
		_D("invalid parameter");
		if (fd >= 0)
			__real_send(fd, -1);
		return -1;
	}

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", caller_pid);
	bundle_add(kb, AUL_K_CALLER_PID, tmp_pid);

	if (cmd == APP_START_RES)
		bundle_add(kb, AUL_K_WAIT_RESULT, "1");

	caller = _status_app_get_appid_bypid(caller_pid);
	if(caller == NULL) {
		ret = aul_app_get_appid_bypid(caller_pid, caller_appid, sizeof(caller_appid));
		if(ret == 0) {
			bundle_add(kb, AUL_K_CALLER_APPID, caller_appid);
		}
	} else {
		bundle_add(kb, AUL_K_CALLER_APPID, caller);
	}
	curr_caller = bundle_get_val(kb,AUL_K_CALLER_APPID);
	SECURE_LOGD("caller : %s", curr_caller);

#ifdef _APPFW_FEATURE_CONTACT_PHONE_AS_ONE_APP
	// Add the appid into bundle to distinguish between Contacts and Phone.
	if (strncmp(appid, "org.tizen.contacts", strlen("org.tizen.contacts")) == 0
		|| strncmp(appid, "org.tizen.phone", strlen("org.tizen.phone")) == 0)
	{
		bundle_add(kb, AUL_K_INTERNAL_APPID, appid);
		SECURE_LOGD("Add the appid[%s] into bundle to distinguish between Contacts and Phone.", appid);
	}
#endif
	ai = appinfo_find(_laf, appid);
	if(ai == NULL) {
		_D("no appinfo");
		__real_send(fd, -1);
		return -1;
	} else {
		pkg_status = appinfo_get_value(ai, AIT_STATUS);
		if(pkg_status && (strncmp(pkg_status, "blocking", 8) == 0 || strncmp(pkg_status, "restart", 7) == 0) ) {
			_D("blocking");
			__real_send(fd, -EREJECTED);
			return -EREJECTED;
		} else if(pkg_status && strncmp(pkg_status, "unmounted", 9) == 0 ) {
			_D("unmounted");
			__real_send(fd, -1);
			return -1;
		}
	}

	app_path = appinfo_get_value(ai, AIT_EXEC);
	pkg_type = appinfo_get_value(ai, AIT_TYPE);
	permission = appinfo_get_value(ai, AIT_PERM);
	pkgid = appinfo_get_value(ai, AIT_PKGID);
	component_type = appinfo_get_value(ai, AIT_COMPTYPE);

	operation = bundle_get_val(kb, "__APP_SVC_OP_TYPE__");
	caller_ai = appinfo_find(_laf, curr_caller);

	if(permission && strncmp(permission, "signature", 9) == 0 ) {
		if(caller_uid != 0 && (cmd == APP_START
					|| cmd == APP_START_RES
					|| cmd == APP_START_ASYNC
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
					|| cmd == APP_START_MULTI_INSTANCE
#endif
					))
		{
			preload = appinfo_get_value(caller_ai, AIT_PRELOAD);
			if( preload && strncmp(preload, "true", 4) != 0 ) {
				pkgmgrinfo_pkginfo_compare_app_cert_info(caller_appid, appid, &compare_result);
				if(compare_result != PMINFO_CERT_COMPARE_MATCH) {
					pid = -EILLEGALACCESS;
					if(cmd == APP_START_ASYNC)
						close(fd);
					else
						__real_send(fd, pid);
					return pid;
				}
			}
		}
	}

	if(__check_mode(ai) < 0) {
		pid = -EREJECTED;
		if(cmd == APP_START_ASYNC)
			close(fd);
		else
			__real_send(fd, pid);
		return pid;
	}

	pkgmgrinfo_client_request_enable_external_pkg(pkgid);

	if (component_type && (strncmp(component_type, "uiapp", strlen("uiapp")) == 0
		|| strncmp(component_type, "watchapp", strlen("watchapp")) == 0
		|| strncmp(component_type, "widgetapp", strlen("widgetapp")) == 0)) {

#ifdef _APPFW_FEATURE_MULTI_WINDOW
		if((cmd != APP_RESUME) && (cmd != APP_OPEN)) {
			__add_multi_window_info(kb, ai, (const char*) appid, (const char*)bundle_get_val(kb,AUL_K_CALLER_APPID));
		}
#endif
		multiple = appinfo_get_value(ai, AIT_MULTI);
		if (!multiple || strncmp(multiple, "false", 5) == 0) {
			pid = _status_app_is_running_v2(appid);
		} else if (operation != NULL && strncmp(operation, "http://tizen.org/appcontrol/operation/view", 512) == 0){
			old_caller = _status_get_caller_by_appid(appid);
			if(old_caller && curr_caller) {
				if(strncmp(old_caller, curr_caller, MAX_PACKAGE_STR_SIZE) == 0) {
					pid = _status_app_is_running_v2(appid);
				}
			}
		}

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
		char app_path_link[512] = {0,};
		const char *caller_app_path = NULL;
		char caller_app_path_link[512] = {0,};

		caller_app_path = appinfo_get_value(caller_ai, AIT_EXEC);

		SECURE_LOGD("callee path(%s) caller path(%s)", app_path, caller_app_path);

		readlink(app_path, app_path_link, 512);
		readlink(caller_app_path, caller_app_path_link, 512);

		SECURE_LOGD("callee link(%s) caller link(%s)", app_path_link, caller_app_path_link);

		if(strncmp(app_path_link, "/usr/bin/ug-client", 512) == 0) {
			if (strcmp(caller, "org.tizen.app-selector") == 0){
				pid = atoi(bundle_get_val(kb,AUL_K_ORG_CALLER_PID));
				bundle_add(kb, "__AUL_UG_EXEC__", app_path);
				SECURE_LOGD("app_path : %s , ug id(%s)", app_path, bundle_get_val(kb, "__AUL_UG_ID__"));
			} else if(strncmp(caller_app_path_link, "/usr/bin/ug-client", 512) == 0) {
				__real_send(fd, -EUGLOCAL_LAUNCH);
				return -1;
			}
		}
#endif

		if(curr_caller) {
			caller_component_type = appinfo_get_value(caller_ai, AIT_COMPTYPE);
			if (caller_component_type && strncmp(caller_component_type, "uiapp", 5) == 0) {
				Ecore_X_Window in_win;
				in_win = _input_window_get();
				if(in_win) {
					ret = ecore_x_pointer_grab(in_win);
					_D("win(%x) ecore_x_pointer_grab(%d)", in_win, ret);
				}
			}
		}

		status = _status_get_app_info_status(pid);
		if (pid > 0 && status != STATUS_DYING) {
			if (caller_pid == pid) {
				SECURE_LOGD("caller process & callee process is same.[%s:%d]", appid, pid);
				pid = -ELOCALLAUNCH_ID;
			} else {
				if(pkg_type && strncmp(pkg_type, "wgt", 3) == 0) {
					__pre_launching_processing(appid);
				}
				proc_group_change_status(PROC_CGROUP_SET_RESUME_REQUEST, pid, appid);
				if ((ret = __nofork_processing(cmd, pid, kb, fd)) < 0) {
					pid = ret;
				} else {
					delay_reply = 1;
				}
			}
		} else if (cmd != APP_RESUME) {
			if(status == STATUS_DYING && pid > 0) {
				r = kill(pid, SIGKILL);
				if (r == -1)
					_D("send SIGKILL: %s", strerror(errno));
			}
			fake_effect = bundle_get_val(kb, "__FAKE_EFFECT__");

#ifdef _APPFW_FEATURE_CPU_BOOST
			if (cmd == APP_OPEN || operation != NULL ||
				(caller != NULL && strcmp(caller, "org.tizen.wnotification2") == 0) ||
				(caller != NULL && strcmp(caller, "org.tizen.wnotiboard-popup") == 0)) {
				char *arr[2];
				char val[32];
				snprintf(val, sizeof(val), "%d", APP_BOOSTING_PERIOD);
				arr[0] = val;
				arr[1] = NULL;
				ret = invoke_dbus_method_sync(SYSTEM_BUS_NAME, SYSTEM_OBJECT_PATH,
						SYSTEM_INTERFACE_NAME, SYSTEM_METHOD_NAME, "i", arr);
				_D("%s-%s : %d", SYSTEM_INTERFACE_NAME, SYSTEM_METHOD_NAME, ret);
			}
#endif
			/*
			 * 	effect_mode = 0
			 * 		default mode : fake effect off, 1.6 MHZ off
			 * 	effect_mode = 1
			 * 		full mode : fake effect on, 1.6 MHZ on
			 * 	effect_mode = 2
			 * 		fake effect mode : fake effect on, 1.6 MHZ off
			 * 	effect_mode = 3
			 * 		1.6 MHZ mode : faek effect off, 1.6MHZ on
			 *
			 */
			vconf_get_int(AMD_EFFECT_IMAGE_ENABLE, &effect_mode);
#ifdef _APPFW_FEATURE_WMS_CONNECTION_CHECK
			vconf_get_bool(VCONFKEY_WMS_WMANAGER_CONNECTED, &wmanager_connected);
#endif
			//_D("*******[effect_mode] Mode : %d\n ", effect_mode );

			if ( ( cmd == APP_OPEN ||
				( (operation != NULL && strncmp(operation, "http://tizen.org/appcontrol/operation/main", 512) == 0)
				&& !(fake_effect != NULL && strncmp(fake_effect, "OFF", 3) == 0) )
				) && (effect_mode == 1 || effect_mode == 2)
#ifdef _APPFW_FEATURE_WMS_CONNECTION_CHECK
				&& wmanager_connected == true
#endif
				){
				char image_filename[256] = {0,};
				char xml_filename[256] = {0,};
				const char *portraitimg = NULL;
				const char *landscapeimg = NULL;
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
				char *effectimg_type = NULL;
#endif
				const char *indicator = NULL;
				int screen_mode = 0;
				bool rotate_allowed = false;
				int file_type = 1;
				int theme = 0;

				//vconf_get_int(PHONE_ORIENTATION_MODE, &screen_mode);
				screen_mode = invoke_dbus_method_sync(ROTATION_BUS_NAME, ROTATION_OBJECT_PATH,
								ROTATION_INTERFACE_NAME, ROTATION_METHOD_NAME, "i", NULL);
				_D("%s-%s : %d", ROTATION_INTERFACE_NAME, ROTATION_METHOD_NAME, screen_mode);
				vconf_get_bool(PHONE_ROTATE_LOCK, &rotate_allowed); /*TODO: use vconf_notify_key_changed()*/
				portraitimg = appinfo_get_value(ai, AIT_EFFECTIMAGEPORT);
				landscapeimg = appinfo_get_value(ai, AIT_EFFECTIMAGELAND);
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
				effectimg_type = appinfo_get_value(ai, AIT_EFFECTTYPE);
#endif
				indicator = appinfo_get_value(ai, AIT_INDICATOR_DISP);
				/*Currently we assume apps supporting launching effect supports portrait mode*/
				if (indicator && portraitimg) {
					if (rotate_allowed == false) {
						screen_mode = 1;
					}
					if ((screen_mode == 2 || screen_mode == 4) && (rotate_allowed == true)) {
						/*if there is no landscape image, that means app supports only portrait mode.*/
						if (landscapeimg) {
							snprintf(image_filename, 255, "%s", landscapeimg);
						}
					} else {
						snprintf(image_filename, 255, "%s", portraitimg);
					}
					if (access(image_filename, R_OK) == 0) {
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
						if(strncmp(effectimg_type, "edj-dark", strlen(effectimg_type)) == 0) {
							file_type = 0;
							theme = 0;
						} else if (strncmp(effectimg_type, "edj-light", strlen(effectimg_type)) == 0) {
							file_type = 0;
							theme = 1;
						} else if (strncmp(effectimg_type, "edj-default", strlen(effectimg_type)) == 0) {
							file_type = 0;
							theme = 2;
						} else {
							file_type = 1;
							theme = 0;
						}

						do {
							if (file_type == 1)
								break;
							r = snprintf(xml_filename, 255, "/usr/apps/%s/shared/res/tables/%s_ChangeableColorInfo.xml", pkgid, pkgid);
							if (access(xml_filename, R_OK) == 0) {
								//snprintf(image_filename, 255, "%s:%s", image_filename, xml_filename);
								strcat(image_filename, ":");
								strcat(image_filename, xml_filename);
								break;
							}
							r = snprintf(xml_filename, 255, "/opt/usr/apps/%s/shared/res/tables/%s_ChangeableColorInfo.xml", pkgid, pkgid);
							if (access(xml_filename, R_OK) == 0) {
								//snprintf(image_filename, 255, "%s:%s", image_filename, xml_filename);
								strcat(image_filename, ":");
								strcat(image_filename, xml_filename);
								break;
							}
						} while(0);
#endif
#ifndef _APPFW_FEATURE_DEFAULT_FAKE_IMAGE
						__amd_effect_image_file_set(image_filename);
#else
						if(file_type == 1) {
							__amd_effect_image_file_set("/usr/share/splash_images/type0_portrait.bmp");
						} else {
							__amd_effect_image_file_set(image_filename);
						}
#endif
						__amd_send_message_to_e17(screen_mode, indicator, file_type, theme);
					}
				}
			}

#ifdef _APPFW_FEATURE_DEBUG_LAUNCHPAD
			if (bundle_get_type(kb, AUL_K_SDK) != BUNDLE_TYPE_NONE) {
				pad_pid = DEBUG_LAUNCHPAD_PID;
			} else if (pkg_type && strncmp(pkg_type, "wgt", 3) == 0) {
				pad_pid = WEB_LAUNCHPAD_PID;
			}
#else
			if (pkg_type && strncmp(pkg_type, "wgt", 3) == 0) {
				pad_pid = WEB_LAUNCHPAD_PID;
			}
#endif
#ifdef _APPFW_FEATURE_NATIVE_LAUNCHPAD
			else if (pkg_type && strncmp(pkg_type, "tpk", 3) == 0) {
                char native_sock[UNIX_PATH_MAX] = { 0, };
                snprintf(native_sock, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, pad_pid);
				if (access(native_sock, F_OK) != 0) {
					_D("Sending to native launchpad because native launchpad is not initialized.");
				} else {
				    pad_pid = NATIVE_LAUNCHPAD_PID;
                }
			}
#endif
#ifdef _APPFW_FEATURE_PROCESS_POOL
			else {
				const char *process_pool = appinfo_get_value(ai, AIT_POOL);
				_D("process_pool: %s", process_pool);

				const char *hwacc = appinfo_get_value(ai, AIT_HWACC);
				_D("h/w acceleration: %s", hwacc);

				SECURE_LOGD("appid: %s", appid);

				if (process_pool && strncmp(process_pool, "true", strlen("true")) == 0)
				{
 #ifndef _APPFW_FEATURE_PROCESS_POOL_COMMON
					if (hwacc && strncmp(hwacc, "USE", strlen("USE")) != 0)
					{
						_D("Sending to process-pool launchpad (type1).");
						bundle_add(kb, AUL_K_LAUNCHPAD_TYPE, "1"); //sw rendering
						pad_pid = PROCESS_POOL_LAUNCHPAD_PID;
					}
					else
					{
  #ifndef _APPFW_FEATURE_PROCESS_POOL_HW_RENDERING
						_D("Sending to legacy launchpad because launchpad type2 is not supported.");
  #else
						_D("Sending to process-pool launchpad (type2).");
						bundle_add(kb, AUL_K_LAUNCHPAD_TYPE, "2"); //hw rendering
						pad_pid = PROCESS_POOL_LAUNCHPAD_PID;
  #endif
					}
 #else //_APPFW_FEATURE_PROCESS_POOL_COMMON
					_D("Sending to process-pool launchpad (combine mode).");
					bundle_add(kb, AUL_K_LAUNCHPAD_TYPE, "1");
					pad_pid = PROCESS_POOL_LAUNCHPAD_PID;
 #endif //_APPFW_FEATURE_PROCESS_POOL_COMMON

					char pad_sock[UNIX_PATH_MAX] = { 0, };
					snprintf(pad_sock, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, pad_pid);
					if (access(pad_sock, F_OK) != 0)
					{
						_D("Sending to legacy launchpad because process-pool launchpad is not initialized.");
						pad_pid = LAUNCHPAD_PID;
					}
				}
			}
#endif //_APPFW_FEATURE_PROCESS_POOL

			__set_appinfo_for_launchpad(ai, kb);
			pid = app_send_cmd(pad_pid, cmd, kb);
			if(pid == AUL_R_ECOMM) {
				pid = -ENOLAUNCHPAD;
			}
			//_add_cgroup(_lcg, appid, pid);
			proc_cgroup_launch(PROC_CGROUP_SET_LAUNCH_REQUEST, pid, appid, pkgid);
			snprintf(trm_buf, MAX_PACKAGE_STR_SIZE, "appinfo_launch:%s[PID]%d", appid, pid);
			__trm_app_info_send_socket(trm_buf);
		}
		if(pid < 0) {
			if(_input_window_get() != 0)
				ecore_x_pointer_ungrab();
			_D("pid(%d) ecore_x_pointer_ungrab", pid);
		} else {
			grab_timer_id = g_timeout_add(1000, __grab_timeout_handler, pid);
		}
	}
	else if (component_type && strncmp(component_type, "svcapp", 6) == 0) {
		pid = _status_app_is_running_v2(appid);
		if (pid > 0) {
			if ((ret = __nofork_processing(cmd, pid, kb, fd)) < 0) {
				pid = ret;
			} else {
				delay_reply = 1;
			}
		} else if (cmd != APP_RESUME) {
#ifdef _APPFW_FEATURE_DEBUG_LAUNCHPAD
			if (bundle_get_type(kb, AUL_K_SDK) != BUNDLE_TYPE_NONE) {
				_D("The svcapp(%s) is launched by debug-launchpad", appid);
				__set_appinfo_for_launchpad(ai, kb);
				pid = app_send_cmd(DEBUG_LAUNCHPAD_PID, cmd, kb);
				if (pid == AUL_R_ECOMM) {
					pid = -ENOLAUNCHPAD;
				}
				proc_cgroup_launch(PROC_CGROUP_SET_LAUNCH_REQUEST, pid, appid, pkgid);
			} else {
				pid = service_start(_lcg, appid, app_path, kb);
				proc_cgroup_launch(PROC_CGROUP_SET_SERVICE_REQUEST, pid, appid, pkgid);
			}
#else
			pid = service_start(_lcg, appid, app_path, kb);
			proc_cgroup_launch(PROC_CGROUP_SET_SERVICE_REQUEST, pid, appid, pkgid);
#endif
		}
	} else {
		_E("unkown application");
	}

	if(!delay_reply) {
		if(cmd == APP_START_ASYNC)
			close(fd);
		else
			__real_send(fd, pid);
	}

	if(pid > 0) {
#ifdef _APPFW_FEATURE_CONTACT_PHONE_AS_ONE_APP
		// Add the appid into bundle to distinguish between Contacts and Phone.
		if (strncmp(appid, "org.tizen.phone", strlen("org.tizen.phone")) == 0)
			_status_add_app_info_list("org.tizen.contacts", app_path, curr_caller, pid, pad_pid);
		else
#endif
			_status_add_app_info_list(appid, app_path, curr_caller, pid, pad_pid);

#ifdef _APPFW_FEATURE_APP_CHECKER
		const char *pkgtype = NULL;

		pkgtype = appinfo_get_value(ai, AIT_TYPE);
		if (pkgtype == NULL) {
			_E("pkgtype is NULL");
			return -1;
		}

		ret = ac_server_check_launch_privilege(appid, pkgtype, pid);
		return ret != AC_R_ERROR ? pid : -1;
#endif
	}

	return pid;
}

int __e17_status_handler(int pid, int status, void *data)
{
	if( status == 0 || status == 3) {
		_D("pid(%d) status(%d)", pid, status);
		if(_input_window_get() != 0)
			ecore_x_pointer_ungrab();
		g_source_remove(grab_timer_id);
	}

	return 0;
}

int _launch_init(struct amdmgr* amd)
{
	int ret = 0;

	_D("_launch_init");

	amd_cmdline = __proc_get_cmdline_bypid(getpid());

	_laf = amd->af;
	_lcg = amd->cg;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		_E("dbus_bus_get error");
		return -EBADMSG;
	}

	ret = aul_listen_e17_status_signal(__e17_status_handler, NULL);

	_D("ret : %d", ret);

	return 0;
}

void _set_atom_effect(void)
{
	ATOM_IMAGE_EFFECT = ecore_x_atom_get(atom_name);
}

void __set_appinfo_for_launchpad(const struct appinfo *ai, bundle *kb) {
	_D("Add hwacc, taskmanage, app_path and pkg_type into bundle for sending those to launchpad.");
	bundle_add(kb, AUL_K_HWACC, appinfo_get_value(ai, AIT_HWACC));
	bundle_add(kb, AUL_K_TASKMANAGE, appinfo_get_value(ai, AIT_TASKMANAGE));
	bundle_add(kb, AUL_K_EXEC, appinfo_get_value(ai, AIT_EXEC));
	bundle_add(kb, AUL_K_PACKAGETYPE, appinfo_get_value(ai, AIT_TYPE));
}
