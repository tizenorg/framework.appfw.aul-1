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
#include <signal.h>
#include <Ecore_X.h>
#include <Ecore_Input.h>
#ifdef _APPFW_FEATURE_AMD_KEY
#include <utilX.h>
#endif
#include <Ecore.h>
#include <Evas.h>
#include <Ecore_Evas.h>
#include <security-server.h>
#include <aul_svc.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <aul.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
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
#include <ttrace.h>
#include <sys/smack.h>
#include <security-server-perm.h>

#ifdef _APPFW_FEATURE_PRIVATE_SERVICE
#include <cert-service.h>
#endif

#include "amd_config.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_key.h"
#include "app_sock.h"
#include "simple_util.h"
#include "launch.h"
#include "app_signal.h"
#include "amd_app_group.h"
#include "amd_request.h"

#define PREEXEC_ACTIVATE
#include "preexec.h"

#define DAC_ACTIVATE
#include "access_control.h"

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#include "appfw_env.h"
#endif

#define TERM_WAIT_SEC 3
#define INIT_PID 1

#define AUL_PR_NAME			16
#define PATH_APP_ROOT "/opt/usr/apps"
#define PATH_DATA "/data"
#define SDK_CODE_COVERAGE "CODE_COVERAGE"
#define SDK_DYNAMIC_ANALYSIS "DYNAMIC_ANALYSIS"
#define PATH_DA_SO "/home/developer/sdk_tools/da/da_probe.so"

#ifdef _APPFW_FEATURE_FAKE_EFFECT
#define PHONE_ORIENTATION_MODE "memory/private/sensor/10001"
#define PHONE_ROTATE_LOCK "db/setting/auto_rotate_screen"
#endif

#define SYS_MIN_CPU_LOCK_FILE "/sys/devices/system/cpu/cpufreq/slp/min_cpu_lock"
#define MIN_CPU_LCK_CNT 0
#define MAX_CPU_LCK_CNT 2

#define HIDE_INDICATOR 0
#define SHOW_INDICATOR 1

#define PROC_STATUS_FG	3
#define PROC_STATUS_BG	4
#ifdef _APPFW_FEATURE_CPU_BOOST
#define APP_BOOSTING_PERIOD 1500 //msec
#endif

#ifdef _APPFW_FEATURE_PRIVATE_SERVICE
#define OSP_K_LAUNCH_TYPE   "__OSP_LAUNCH_TYPE__"
#define OSP_V_LAUNCH_TYPE_DATACONTROL	"datacontrol"
#endif

static char *amd_cmdline;

struct appinfomgr *_laf;

DBusConnection *conn;
#ifdef _APPFW_FEATURE_AMD_KEY
guint grab_timer_id;
#endif


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
static void __set_reply_handler(int fd, int pid, int clifd, int cmd);
static void __real_send(int clifd, int ret);
static int __send_proc_prelaunch_signal(const char *appid, const char *pkgid, int attribute);
int invoke_dbus_method_sync(const char *dest, const char *path,
			    const char *interface, const char *method,
			    const char *sig, char *param[]);

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

static void __set_oom(void)
{
	char buf[MAX_OOM_ADJ_BUFSZ] = {0,};
	FILE *fp = NULL;

	/* we should reset oomadj value as default because child
	inherits from parent oom_adj*/
	snprintf(buf, MAX_OOM_ADJ_BUFSZ, "/proc/%d/oom_score_adj", getpid());
	fp = fopen(buf, "w");
	if (fp == NULL)
		return;
	fprintf(fp, "%d", 100);
	fclose(fp);
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

	__set_oom();

	ai = appinfo_find(_laf, appid);

	app_path = appinfo_get_value(ai, AIT_EXEC);
	pkg_type = appinfo_get_value(ai, AIT_TYPE);
	hwacc = appinfo_get_value(ai, AIT_HWACC);

	__preexec_run(pkg_type, appid, app_path);

	/* SET PRIVILEGES*/
	 SECURE_LOGD("appid : %s / pkg_type : %s / app_path : %s ", appid, pkg_type, app_path);
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

static char **__create_argc_argv(bundle * kb, int *margc)
{
	char **argv;
	int argc;

	argc = bundle_export_to_argv(kb, &argv);

	*margc = argc;
	return argv;
}
static void _do_exec(const char *cmd, const char *group, bundle *kb)
{
	gchar **argv;
	gint argc;
	char **b_argv;
	int b_argc;
	gboolean b;

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

	_W("send launch signal done: %d", launch_pid);

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

#ifdef _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT
	if(_status_get_cooldown_status() == COOLDOWN_LIMIT) {
		_E("[Info]cooldown status : LimitAction");
		return -1;
	}
#endif // _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT

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

	_W("send a watchdog signal done: %d", pid);

	return 0;
}

static int __send_proc_prelaunch_signal(const char *appid, const char *pkgid, int attribute)
{
	DBusMessage *message;

	if (conn == NULL)
		return -1;

	message = dbus_message_new_signal(RESOURCED_PROC_OBJECT,
					  RESOURCED_PROC_INTERFACE,
					  RESOURCED_PROC_PRELAUNCH_SIGNAL);

	if (dbus_message_append_args(message,
					 DBUS_TYPE_STRING, &appid,
					 DBUS_TYPE_STRING, &pkgid,
				     DBUS_TYPE_INT32, &attribute,
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

	SECURE_LOGW("send a prelaunch signal done: appid(%s) pkgid(%s) attribute(%x)", appid, pkgid, attribute);

	return 0;
}

static int __check_cmdline(int ret)
{
	char *cmdline;
	int wait_count;
	int cmdline_changed = 0;
	int cmdline_exist = 0;

	if (ret <= 1)
		return -1;

	/* check normally was launched?*/
	wait_count = 1;
	do {
		cmdline = __proc_get_cmdline_bypid(ret);
		if (cmdline == NULL) {
			_E("error founded when being launched with %d", ret);
			if (cmdline_exist || cmdline_changed) {
				_E("The app process might be terminated while we are wating %d", ret);
				break;
			}
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
		_E("cmdline_exist 0 & cmdline_changed 0");
		return -1;
	}

	if (!cmdline_changed)
		_E("process launched, but cmdline not changed");

	return ret;
}

int start_process(const char *group, const char *cmd, bundle *kb)
{
	int r;
	pid_t p;

	p = fork();
	switch (p) {
	case 0: /* child process */
		_D("start application");
		_signal_unblock_sigchld();
#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
		r = setpriority(PRIO_PROCESS, 0, 0);
		if (r == -1)
		{
			SECURE_LOGE("Setting process (%d) priority to 0 failed, errno: %d (%s)",
					getpid(), errno, strerror(errno));
		}
#endif
		_do_exec(cmd, group, kb);
		/* exec error */

		exit(0);
		break;
	case -1:
		_E("application start: fork: %s", strerror(errno));
		r = -1;
		break;
	default: /* parent process */
		_W("child process: %d", p);
		r = __check_cmdline(p);
		if(r > 0)
			__send_app_launch_signal(r);
		else
			_E("cmdline change failed.");
		break;
	}

	return r;
}

static int __check_ver(const char *required, const char *actual)
{
	int ret = 0;
	if (required && actual) {
		ret = strverscmp(required, actual); // should 0 or less
		if (ret < 1)
			return 1;
	}

	return 0;
}

static int __get_prelaunch_attribute(const struct appinfo *ai)
{
	int attribute_val = 0;
	const char *attribute_str = NULL;

	attribute_str = appinfo_get_value(ai, AIT_ALLOWED_BG);
	if (attribute_str && strncmp(attribute_str, "ALLOWED_BG", sizeof("ALLOWED_BG")) == 0) {
		attribute_val |= RESOURCED_ALLOWED_BG_ATTRIBUTE;
	}

#ifdef _APPFW_FEATURE_BACKGROUND_MANAGEMENT
	attribute_val |= RESOURCED_BACKGROUND_MANAGEMENT_ATTRIBUTE;
#endif

	attribute_str = appinfo_get_value(ai, AIT_API_VER);
	if (attribute_str && __check_ver("2.4", attribute_str)) {
		attribute_val |= RESOURCED_API_VER_2_4_ATTRIBUTE;
	}

	return attribute_val;
}

int _start_srv(const struct appinfo *ai)
{
	int r;
	bundle *b = NULL;
	const char *group;
	const char *cmd;
	const char *pkgid;
	const char *appid = NULL;
	int prelaunch_attribute = 0;

	group = appinfo_get_filename(ai);

	cmd = appinfo_get_value(ai, AIT_EXEC);
	if (!cmd) {
		_E("start service: '%s' has no exec", group);
		return -1;
	}

	appid = appinfo_get_value(ai, AIT_NAME);
	pkgid = appinfo_get_value(ai, AIT_PKGID);

	prelaunch_attribute = __get_prelaunch_attribute(ai);
	if ((prelaunch_attribute & RESOURCED_ALLOWED_BG_ATTRIBUTE) ||
		!(prelaunch_attribute & RESOURCED_API_VER_2_4_ATTRIBUTE)) {
		SECURE_LOGD("[__SUSPEND__] allowed background, appid :%s, app_type: %s, api version: %s",
			appid, APP_TYPE_SERVICE, appinfo_get_value(ai,  AIT_API_VER));
		if (b == NULL) {
			b = bundle_create();
		}

		bundle_add(b, AUL_K_ALLOWED_BG, "ALLOWED_BG");
	}

	__send_proc_prelaunch_signal(appid, pkgid, prelaunch_attribute);

	r = start_process(group, cmd, b);
	if (b) {
		bundle_free(b);
		b = NULL;
	}

	if (r == -1) {
		_E("start service: '%s': failed", group);

		return -1;
	}

	aul_send_app_launch_request_signal(r, group, pkgid, APP_TYPE_SERVICE);
	_status_add_app_info_list(group, cmd, NULL, r, -1, 0);

	return 0;
}

static void _free_kt(struct ktimer *kt)
{
	if (!kt)
		return;

	free(kt->group);
	free(kt);
}

static void _kill_pid(struct cginfo *cg, const char *group, pid_t pid)
{
	int r;

	if (pid <= INIT_PID) /* block sending to all process or init */
		return;

	/* TODO: check pid exist in group */

	r = kill(pid, 0);
	if (r == -1) {
		_E("send SIGKILL: pid %d not exist", pid);
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
	_W("resume done\n");

	if (ret > 0)
		__set_reply_handler(ret, pid, clifd, APP_RESUME_BY_PID);

	return ret;
}

int _pause_app(int pid, int clifd)
{
	int dummy;
	int ret;
	if ((ret =
	    __app_send_raw_with_delay_reply(pid, APP_PAUSE_BY_PID, (unsigned char *)&dummy,
			    sizeof(int))) < 0) {
		if (ret == -EAGAIN)
			_E("pause packet timeout error");
		else {
			_E("iconify failed - %d pause fail\n", pid);
			_E("we will term the app - %d\n", pid);
			_send_to_sigkill(pid);
			ret = -1;
		}
	}
	_D("pause done\n");

	if (ret > 0)
		__set_reply_handler(ret, pid, clifd, APP_PAUSE_BY_PID);

	return ret;
}

int _fake_launch_app(int cmd, int pid, bundle * kb, int clifd)
{
	int datalen;
	int ret;
	bundle_raw *kb_data = NULL;

	if (!kb){
		__real_send(clifd, -EINVAL);
		return -EINVAL;
	}

	ret = bundle_encode(kb, &kb_data, &datalen);
	if (ret != BUNDLE_ERROR_NONE) {
		__real_send(clifd, -EINVAL);
		return -EINVAL;
	}
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
	if(clifd <= 0) {
		return;
	}
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
		if (cmd == APP_TERM_BY_PID || cmd == APP_TERM_BGAPP_BY_PID) {
			__real_send(clifd, -1);
		} else if (cmd == APP_START_ASYNC || cmd == APP_PAUSE_BY_PID) {
			close(clifd);
		} else {
			__real_send(clifd, res);
		}
	} else {
		if (cmd == APP_TERM_BY_PID || cmd == APP_TERM_BGAPP_BY_PID) {
			__real_send(clifd, 0);
		} else if (cmd == APP_START_ASYNC || cmd == APP_PAUSE_BY_PID) {
			close(clifd);
		} else {
			__real_send(clifd, pid);
		}
	}

	_W("listen fd(%d) , send fd(%d), pid(%d), cmd(%d)", fd, clifd, pid, cmd);

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
	char *appid = NULL;
	const struct appinfo *ai;
	int task_manage = 0;

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
		appid = _status_app_get_appid_bypid(r_info->pid);
		if(appid == NULL)
			break;
		ai = appinfo_find(_laf, appid);
		if(ai == NULL) {
			_E("ai is NULL");
			break;
		}
		task_manage = appinfo_get_boolean(ai, AIT_TASKMANAGE);
		if(task_manage) {
			__send_watchdog_signal(r_info->pid, SIGKILL);
		}
		break;
	case APP_TERM_BY_PID:
	case APP_TERM_BGAPP_BY_PID:
		if (_send_to_sigkill(r_info->pid) < 0) {
			_E("fail to killing - %d\n", r_info->pid);
			__real_send(r_info->clifd, -1);
		} else {
			__real_send(r_info->clifd, 0);
		}
		break;
	}

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
		return;
	}
	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	r_info = malloc(sizeof(*r_info));
	if (r_info == NULL) {
		_E("out of memory");
		g_free(gpollfd);
		g_source_unref(src);
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

void _term_sub_app(int pid)
{
	int dummy;
	int ret;

	if ( (ret = __app_send_raw_with_noreply(pid, APP_TERM_BY_PID_ASYNC,
					(unsigned char *)&dummy, sizeof(int))) < 0) {
		_E("terminate packet send error - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			return;
		}
	}
}

int _term_app(int pid, int clifd)
{
	int dummy;
	int ret;

	if (app_group_is_leader_pid(pid)) {
		int cnt;
		int *pids = NULL;
		int i;

		app_group_get_group_pids(pid, &cnt, &pids);
		if (cnt > 0) {
			for (i = cnt-1 ; i>=0; i--) {
				if (i != 0)
					_term_sub_app(pids[i]);
				app_group_remove(pids[i]);

			}
		}
		if (pids)
			free(pids);
	}

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

int _term_req_app(int pid, int clifd)
{
	int dummy;
	int ret;

	if ( (ret = __app_send_raw_with_delay_reply
		(pid, APP_TERM_REQ_BY_PID, (unsigned char *)&dummy, sizeof(int))) < 0) {
		_D("terminate req send error");
		__real_send(clifd, ret);
	}

	if (ret > 0)
		__set_reply_handler(ret, pid, clifd, APP_TERM_REQ_BY_PID);

	return 0;
}

int _term_bgapp(int pid, int clifd)
{
	int dummy;
	int fd;

	if (app_group_is_leader_pid(pid)) {
		int cnt;
		int *pids = NULL;
		int i;
		int status = -1;

		app_group_get_group_pids(pid, &cnt, &pids);
		if (cnt > 0) {
			status = _status_get_app_info_status(pids[cnt-1]);
			if(status == STATUS_BG) {
				for (i = cnt-1 ; i>=0; i--) {
					if (i != 0)
						_term_sub_app(pids[i]);
					app_group_remove(pids[i]);
				}
			}
		}
		if (pids)
			free(pids);
	}

	if ( (fd = __app_send_raw_with_delay_reply
	    (pid, APP_TERM_BGAPP_BY_PID, (unsigned char *)&dummy, sizeof(int))) < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			__real_send(clifd, -1);
			return -1;
		}
		__real_send(clifd, 0);
	}
	_D("term_bgapp done\n");
	if (fd > 0)
		__set_reply_handler(fd, pid, clifd, APP_TERM_BGAPP_BY_PID);

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
            struct dirent entry, *result = NULL;

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
#ifdef _APPFW_FEATURE_CPU_BOOST
	const char *operation;

	operation = bundle_get_val(kb, "__APP_SVC_OP_TYPE__");

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
	_W("__nofork_processing, cmd: %d, pid: %d", cmd, pid);
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

	default:
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

#ifdef _APPFW_FEATURE_FAKE_EFFECT
static void __amd_effect_image_file_set(char *image_file)
{
	Ecore_X_Window root_win;

	if(!_window_is_initialized())
		return;

	root_win = ecore_x_window_root_first_get();
	SECURE_LOGD("path : %s", image_file);
	ecore_x_window_prop_string_set(root_win, ATOM_IMAGE_EFFECT,image_file);
}


static void __amd_send_message_to_e17(int screenmode, const char * indicator, int effect_type, int theme)
{
	Ecore_X_Window root_win;
	int ret;

	if(!_window_is_initialized())
		return;

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
#endif

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

#ifdef _APPFW_FEATURE_AMD_KEY
static gboolean __grab_timeout_handler(gpointer data)
{
	int pid = (int) data;

	if(_input_window_get() != 0)
		ecore_x_pointer_ungrab();
	_D("pid(%d) ecore_x_pointer_ungrab", pid);
	if(_key_ungrab(KEY_BACK) < 0) {
		_W("back key ungrab error");
	} else {
		_D("back key ungrab");
	}

	return FALSE;
}
#endif

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
static int __tep_mount(char *mnt_path[])
{
	DBusMessage *msg;
	int func_ret = 0;
	int rv = 0;
	struct stat link_buf = {0,};

	rv = lstat(mnt_path[0], &link_buf);
	if (rv == 0) {
		rv = unlink(mnt_path[0]);
		if (rv)
			_E("Unable tp remove link file %s", mnt_path[0]);
	}

	msg = dbus_message_new_method_call(TEP_BUS_NAME, TEP_OBJECT_PATH,
	                                   TEP_INTERFACE_NAME, TEP_MOUNT_METHOD);
	if (!msg) {
		_E("dbus_message_new_method_call(%s:%s-%s)", TEP_OBJECT_PATH,
		   TEP_INTERFACE_NAME, TEP_MOUNT_METHOD);
		return -1;
	}

	if (!dbus_message_append_args(msg,
	                              DBUS_TYPE_STRING, &mnt_path[0],
	                              DBUS_TYPE_STRING, &mnt_path[1],
	                              DBUS_TYPE_INVALID)) {
		_E("Ran out of memory while constructing args\n");
		func_ret = -1;
		goto func_out;
	}

	if (dbus_connection_send(conn, msg, NULL) == FALSE) {
		_E("dbus_connection_send error");
		func_ret = -1;
		goto func_out;
	}
func_out :
	dbus_message_unref(msg);
	return func_ret;
}

static void __send_mount_request(const struct appinfo *ai, const char *tep_name,
                                 bundle *kb)
{
	SECURE_LOGD("tep name is: %s", tep_name);
	char *mnt_path[2] = {NULL, };
	const char *installed_storage = NULL;
	char tep_path[PATH_MAX] = {0, };

	const char *pkgid = appinfo_get_value(ai, AIT_PKGID);
	installed_storage = appinfo_get_value(ai, AIT_STORAGE_TYPE);
	if (installed_storage != NULL) {
		SECURE_LOGD("storage: %s", installed_storage);
		if (strncmp(installed_storage, "internal", 8) == 0) {
			snprintf(tep_path, PATH_MAX, "%s%s/res/%s", appfw_env_get_apps_path(), pkgid,
			         tep_name);
			mnt_path[1] = strdup(tep_path);
			snprintf(tep_path, PATH_MAX, "%s%s/res/tep", appfw_env_get_apps_path(), pkgid);
			mnt_path[0] = strdup(tep_path);
		} else if (strncmp(installed_storage, "external", 8) == 0) {
			snprintf(tep_path, PATH_MAX, "%step/%s", appfw_env_get_external_storage_path(),
			         tep_name);
			mnt_path[1] = strdup(tep_path);
			snprintf(tep_path, PATH_MAX, "%step/tep-access",
			         appfw_env_get_external_storage_path()); /* TODO : keeping tep/tep-access for now for external storage */
			mnt_path[0] = strdup(tep_path);
		}

		if (mnt_path[0] && mnt_path[1]) {
			bundle_add(kb, AUL_TEP_PATH, mnt_path[0]);
			int ret = -1;
			ret = aul_is_tep_mount_dbus_done(mnt_path[0]);
			if (ret != 1) {
				ret = __tep_mount(mnt_path);
				if (ret < 0)
					_E("dbus error %d", ret);
			}
		}
		if (mnt_path[0])
			free(mnt_path[0]);
		if (mnt_path[1])
			free(mnt_path[1]);
	}
}
#endif

static int __check_app_control_privilege(const char *operation, int caller_pid, const struct appinfo *caller)
{
	int ret;
	const char *api_ver;

	if (caller == NULL) // daemon
		return 0;

	if (operation == NULL || caller_pid < 1)
		return 0;

	if (strcmp(operation, AUL_SVC_OPERATION_DOWNLOAD) == 0) {
		api_ver = appinfo_get_value(caller, AIT_API_VER);

		if (!api_ver) {
			_E("failed to get api version");
			return -1;
		}

		if (api_ver && strverscmp("2.4", api_ver) < 1) { // ver 2.4 or later
			ret = security_server_check_privilege_by_pid(caller_pid, "privilege::tizen::download", "rw");
			if (ret != SECURITY_SERVER_API_SUCCESS) {
				_E("caller %d violates http://tizen.org/privilege/download privilege", caller_pid);
				return -EILLEGALACCESS;
			}
		}
	} else if (strcmp(operation, AUL_SVC_OPERATION_CALL) == 0) {
		// Check the privilege for call operation
		ret = security_server_check_privilege_by_pid(caller_pid, "privilege::tizen::call", "rw");
		if (ret != SECURITY_SERVER_API_SUCCESS) {
			_E("caller %d violates http://tizen.org/privilege/call privilege", caller_pid);
			return -EILLEGALACCESS;
		}
	}

	return 0;
}


int __check_mode(const struct appinfo *ai)
{
#ifdef _APPFW_FEATURE_TTS_MODE
	int tts_mode = 0;
	const char *tts_support = NULL;
#endif
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	int ups_mode = 0;
#endif

#ifdef _APPFW_FEATURE_TTS_MODE
	vconf_get_bool(VCONFKEY_SETAPPL_ACCESSIBILITY_TTS, &tts_mode);
	if(tts_mode) {
		tts_support = appinfo_get_value(ai, AIT_TTS);
		_W("tts : %d %s", tts_mode, tts_support);
		if(strncmp(tts_support, "false", 5) == 0) {
			_W("Cannot launch this app in TTS mode");
			return -1;
		}
	}
#endif

#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	vconf_get_int(VCONFKEY_SETAPPL_PSMODE, &ups_mode);
	if (ups_mode == SETTING_PSMODE_EMERGENCY) {
		const char *ups_support = appinfo_get_value(ai, AIT_UPS);
		_W("ups : %d %s", ups_mode, ups_support);
	}
#endif //_APPFW_FEATURE_ULTRA_POWER_SAVING_MODE

	return 0;
}

static void __prepare_to_suspend_services(int pid)
{
	int dummy;
	SECURE_LOGD("[__SUSPEND__] pid: %d", pid);
	__app_send_raw_with_noreply(pid, APP_SUSPEND, (unsigned char *)&dummy, sizeof(int));
}

static void __prepare_to_wake_services(int pid)
{
	int dummy;
	SECURE_LOGD("[__SUSPEND__] pid: %d", pid);
	__app_send_raw_with_noreply(pid, APP_WAKE, (unsigned char *)&dummy, sizeof(int));
}

static gboolean __check_service_only(gpointer user_data)
{
	int pid = GPOINTER_TO_INT(user_data);
	SECURE_LOGD("[__SUSPEND__] pid :%d", pid);

	_status_check_service_only(pid, __prepare_to_suspend_services);

	return FALSE;
}

#ifdef _APPFW_FEATURE_PRIVATE_SERVICE
static int __get_visibility_from_cert_svc(const char *pkgid, int *visibility)
{
	int ret = 0;
	const char *cert_value = NULL;
	pkgmgrinfo_certinfo_h certinfo = NULL;

	ret = pkgmgrinfo_pkginfo_create_certinfo(&certinfo);
	if (ret != 0) {
		_E("pkgmgrinfo_pkginfo_create_certinfo() failed.");
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, certinfo);
	if (ret != 0) {
		_E("pkgmgrinfo_pkginfo_load_certinfo() failed.");
		ret = -1;
		goto end;
	}

	ret = pkgmgrinfo_pkginfo_get_cert_value(certinfo, PMINFO_DISTRIBUTOR_ROOT_CERT,
						&cert_value);
	if (ret != 0 || cert_value == NULL) {
		_E("pkgmgrinfo_pkginfo_get_cert_value() failed.");
		ret = -1;
		goto end;
	}

	ret = cert_svc_get_visibility_by_root_certificate(cert_value,
		strlen(cert_value), visibility);
	if (ret != 0) {
		_E("cert_svc_get_visibility_by_root_cert() failed. err = [%d]", ret);
		ret = -1;
		goto end;
	}
	_D("visibility = [%d]", *visibility);

end:
	pkgmgrinfo_pkginfo_destroy_certinfo(certinfo);
	return ret;
}
#endif

static int __can_share(const char *path, const char *pkgid)
{
	struct stat path_stat;

	if (access(path, F_OK) != 0)
		return -1;

	if (stat(path, &path_stat) != 0)
		return -1;

	if (!S_ISREG(path_stat.st_mode))
		return -1;

	char buf[1024];

	snprintf(buf, sizeof(buf) - 1, "/opt/usr/apps/%s/data/", pkgid);
	if (strncmp(path, buf, strlen(buf)) != 0)
		return -1;

	return 0;
}

static int __get_current_security_attribute(int pid, char *buf, int size)
{
	int fd;
	int ret;
	char path[1024] = { 0, };

	snprintf(path, sizeof(path) - 1, "/proc/%d/attr/current", pid);
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

	return 0;
}

static int __get_exec_label_by_pid(int pid, char** exec_label)
{
	const char *appid = NULL;
	const char *exec = NULL;
	const char *type = NULL;
	const struct appinfo *ai = NULL;
	char attr[1024] = { 0, };

	if (__get_current_security_attribute(pid, attr, sizeof(attr)) == 0) {
		*exec_label = strdup(attr);
		return 0;
	}

	appid = _status_app_get_appid_bypid(pid);
	if (appid) {
		ai = appinfo_find(_laf, appid);
		exec = appinfo_get_value(ai, AIT_EXEC);
		type = appinfo_get_value(ai, AIT_TYPE);

		if (exec && type) {
			if (strcmp("wgt", type) == 0) {
				if (smack_lgetlabel(exec, exec_label, SMACK_LABEL_EXEC) == 0)
					return 0;
			} else {
				if (smack_getlabel(exec, exec_label, SMACK_LABEL_EXEC) == 0)
					return 0;
			}
		}
	}

	return -1;
}

static int __get_exec_label_by_appid(const char *appid, char** exec_label)
{
	const char *exec = NULL;
	const char *type = NULL;
	const struct appinfo *ai = NULL;

	if (appid) {
		ai = appinfo_find(_laf, appid);
		exec = appinfo_get_value(ai, AIT_EXEC);
		type = appinfo_get_value(ai, AIT_TYPE);

		if (exec && type) {
			if (strcmp("wgt", type) == 0) {
				if (smack_lgetlabel(exec, exec_label, SMACK_LABEL_EXEC) == 0)
					return 0;
			} else {
				if (smack_getlabel(exec, exec_label, SMACK_LABEL_EXEC) == 0)
					return 0;
			}
		}
	}

	return -1;
}

static int __get_owner_pid(int caller_pid, bundle *kb)
{
	char *org_caller = NULL;

	if (bundle_get_str(kb, AUL_K_ORG_CALLER_PID, &org_caller) == BUNDLE_ERROR_NONE) {
		int org_caller_pid = atoi(org_caller);
		char *c_exec_label = NULL;

		if (__get_exec_label_by_pid(caller_pid, &c_exec_label) == 0) {

			if (c_exec_label &&
				(strcmp(APP_SELECTOR, c_exec_label) == 0 ||
				strcmp(SHARE_PANEL, c_exec_label) == 0))
					caller_pid = org_caller_pid;
		}

		if (c_exec_label)
			free(c_exec_label);
	}

	return caller_pid;
}

static int __get_exec_label(char **caller_exec_label, char **callee_exec_label,
				int caller_pid, const char *appid)
{
	char *label_caller = NULL;
	char *label = NULL;

	if (__get_exec_label_by_pid(caller_pid, &label_caller) != 0) {
		return -1;
	}

	if (__get_exec_label_by_appid(appid, &label) != 0) {
		free(label_caller);
		return -1;
	}

	*caller_exec_label = label_caller;
	*callee_exec_label = label;
	return 0;
}

static int __grant_temporary_permission(int caller_pid, const char *appid, bundle *kb,
					char **out_caller_exec_label, char **out_callee_exec_label,
					char ***out_paths)
{
	int type = bundle_get_type(kb, AUL_SVC_DATA_PATH);
	char *path = NULL;
	const char **path_array = NULL;
	int len;
	char *caller_exec_label = NULL;
	char *callee_exec_label = NULL;
	int i;
	char **paths = NULL;
	int ret = -1;
	int owner_pid = -1;
	const char *tmp_appid = NULL;
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;

	switch (type) {
		case BUNDLE_TYPE_STR:
			bundle_get_str(kb, AUL_SVC_DATA_PATH, &path);

			if (!path) {
				_E("path was null");
				goto check_uri;
			}

			owner_pid = __get_owner_pid(caller_pid, kb);
			owner_pid = getpgid(owner_pid); /* for webapp */
			tmp_appid = _status_app_get_appid_bypid(owner_pid);

			ai = appinfo_find(_laf, tmp_appid);
			pkgid = appinfo_get_value(ai, AIT_PKGID);

			if (__can_share(path, pkgid) != 0) {
				_E("__can_share() returned an error");
				goto check_uri;
			}

			if (__get_exec_label(&caller_exec_label, &callee_exec_label, owner_pid,
				appid) != 0) {
				_E("__get_exec_label() returned an error");
				goto finally;
			}

			paths = (char**)malloc(sizeof(char*) * 3);
			if (!paths) {
				_E("Out of memory");
				goto finally;
			}

			paths[0] = strdup(path);
			paths[1] = NULL;
			paths[2] = NULL;
			ret = 0;
			break;

		case BUNDLE_TYPE_STR_ARRAY:
			path_array = bundle_get_str_array(kb, AUL_SVC_DATA_PATH, &len);
			if (!path_array || len <= 0) {
				_E("path_array was null");
				goto check_uri;
			}

			owner_pid = __get_owner_pid(caller_pid, kb);
			owner_pid = getpgid(owner_pid); /* for webapp */
			tmp_appid = _status_app_get_appid_bypid(owner_pid);
			ai = appinfo_find(_laf, tmp_appid);
			pkgid = appinfo_get_value(ai, AIT_PKGID);

			if (__get_exec_label(&caller_exec_label, &callee_exec_label, owner_pid,
				appid) != 0) {
				_E("__get_exec_label() returned an error");
				goto finally;
			}

			paths = (char**)malloc(sizeof(char*) * (len + 2));
			if (!paths) {
				_E("Out of memory");
				goto finally;
			}

			int cnt = 0;
			for (i = 0; i < len; i++) {
				if (__can_share(path_array[i], pkgid) == 0) {
					paths[cnt++] = strdup(path_array[i]);
				}
			}
			if (cnt > 0){
				paths[cnt] = NULL;
				paths[cnt + 1] = NULL;
				ret = 0;
			} else {
				free(paths);
				paths = NULL;
			}
			break;
	}

check_uri:
	if (bundle_get_str(kb, AUL_SVC_K_URI, &path) == BUNDLE_ERROR_NONE) {
		if (!path) {
			_E("path was null");
			goto finally;
		}

		if (strncmp(path, "file://", 7) == 0)
			path = &path[7];
		else {
			_E("file wasn't started with file://");
			goto finally;
		}

		if (owner_pid == -1) {
			owner_pid = __get_owner_pid(caller_pid, kb);
			owner_pid = getpgid(owner_pid); /* for webapp */
		}

		tmp_appid = _status_app_get_appid_bypid(owner_pid);
		ai = appinfo_find(_laf, tmp_appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		if (__can_share(path, pkgid) != 0) {
			_E("__can_share() returned an error");
			goto finally;
		}

		if (!caller_exec_label && !callee_exec_label)
			if (__get_exec_label(&caller_exec_label, &callee_exec_label, owner_pid,
				appid) != 0) {
				_E("__get_exec_label() returned an error");
				goto finally;
			}

		if (!paths) {
			paths = (char**)malloc(sizeof(char*) * 2);
			if (!paths) {
				_E("Out of memory");
				goto finally;
			}

			paths[0] = strdup(path);
			paths[1] = NULL;
		} else {
			i = 0;
			while (1) {
				if (paths[i] == NULL) {
					paths[i] = strdup(path);
					break;
				}
				i++;
			}
		}
		ret = 0;
	}
finally:
	if (ret == 0 && caller_exec_label && paths) {
		_D("grant permission %s : %s : %s", paths[0], caller_exec_label,
			callee_exec_label);
		int r = security_server_perm_apply_sharing(NULL, (const char**)paths, caller_exec_label, callee_exec_label);
		if (r != SECURITY_SERVER_API_SUCCESS) {
			_E("security_server_perm_apply_sharing() returned an error %d",r);
			ret = -1;
		} else {
			*out_caller_exec_label = caller_exec_label;
			*out_callee_exec_label = callee_exec_label;
			*out_paths = paths;

			caller_exec_label = NULL;
			callee_exec_label = NULL;
			paths = NULL;
		}
	}

	if (caller_exec_label)
		free(caller_exec_label);
	if (callee_exec_label)
		free(callee_exec_label);
	if (paths) {
		i = 0;
		while (1) {
			if (paths[i] == NULL) {
				free(paths);
				break;
			}
			free(paths[i]);
			i++;
		}
	}
	return ret;
}

static void __add_shared_info(int pid, const char *caller_exec_label, const char *callee_exec_label, char **paths)
{
	_status_set_exec_label(pid, callee_exec_label);
	_status_add_shared_info(pid, caller_exec_label, paths);
}

int _revoke_temporary_permission(int pid)
{
	GList *list = _status_get_shared_info_list(pid);
	const char *callee_label = _status_get_exec_label(pid);

	if (!list || !callee_label) {
		_E("list or callee_label was null");
		return -1;
	}

	while (list) {
		shared_info_t *sit = (shared_info_t*)list->data;

		_D("revoke permission %s : %s", sit->owner_exec_label, callee_label);
		int r = security_server_perm_drop_sharing(NULL, (const char**)sit->paths,
				sit->owner_exec_label, callee_label);

		if (r != SECURITY_SERVER_API_SUCCESS)
			_E("revoke error %d",r);

		list = g_list_next(list);
	}
	return _status_clear_shared_info_list(pid);
}

int _start_app(const char* appid, bundle* kb, int cmd, int caller_pid, uid_t caller_uid, int fd)
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
	char caller_appid[256] = {0,};
	char* caller = NULL;
	char* old_caller = NULL;
	pkgmgrinfo_cert_compare_result_type_e compare_result;
	int delay_reply = 0;
	int pad_pid = NO_LAUNCHPAD_PID;
	int status = -1;
	int r = -1;
	char trm_buf[MAX_PACKAGE_STR_SIZE];
	gboolean is_group_app = FALSE;
#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
	char log_status[AUL_PR_NAME] = {0,};
#endif

#ifdef _APPFW_FEATURE_FAKE_EFFECT
	const char *fake_effect;
	int effect_mode = 0;
#ifdef _APPFW_FEATURE_WMS_CONNECTION_CHECK
	int wmanager_connected = 0;
#endif

#endif /* _APPFW_FEATURE_FAKE_EFFECT */

#ifdef _APPFW_FEATURE_AMD_KEY
	const char *caller_component_type = NULL;
#endif
	int prelaunch_attribute = 0;

	bool bg_allowed = false;
	int lpid;
	gboolean can_attach;
	app_group_launch_mode launch_mode;
	char *caller_exec_label = NULL;
	char *callee_exec_label = NULL;
	char **paths = NULL;
	int grant_permission = 0;

	traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "AUL:AMD:START_APP");
	if (appid == NULL || kb == NULL
		|| caller_pid < 0 || fd < 0) {
		_D("invalid parameter");
		if (fd >= 0)
			__real_send(fd, -1);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
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
			caller = caller_appid;
		} else {
			_E("no caller appid info, ret: %d", ret);
		}
	} else {
		bundle_add(kb, AUL_K_CALLER_APPID, caller);
	}

	if (caller)
		SECURE_LOGW("caller appid : %s", caller);

	_W("caller pid : %d", caller_pid);

	ai = appinfo_find(_laf, appid);
	if(ai == NULL) {
		_E("no appinfo");
		__real_send(fd, -ENOAPP);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		return -1;
	} else {
		pkg_status = appinfo_get_value(ai, AIT_STATUS);
		if(pkg_status && (strncmp(pkg_status, "blocking", 8) == 0 || strncmp(pkg_status, "restart", 7) == 0) ) {
			_D("blocking");
			__real_send(fd, -EREJECTED);
			traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
			return -EREJECTED;
		} else if(pkg_status && strncmp(pkg_status, "unmounted", 9) == 0 ) {
			_D("unmounted");
			__real_send(fd, -1);
			traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
			return -1;
		}
	}

	app_path = appinfo_get_value(ai, AIT_EXEC);
	pkg_type = appinfo_get_value(ai, AIT_TYPE);
	permission = appinfo_get_value(ai, AIT_PERM);
	pkgid = appinfo_get_value(ai, AIT_PKGID);
	component_type = appinfo_get_value(ai, AIT_COMPTYPE);

	if (pkg_type == NULL)
		pkg_type = "unknown";

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	const char *tep_name = NULL;

	tep_name = appinfo_get_value(ai, AIT_TEP);
	if (tep_name != NULL) {
		__send_mount_request(ai, tep_name, kb);
	}
#endif
	operation = bundle_get_val(kb, "__APP_SVC_OP_TYPE__");
	caller_ai = appinfo_find(_laf, caller);
#ifdef _APPFW_FEATURE_AMD_KEY
	caller_component_type = appinfo_get_value(caller_ai, AIT_COMPTYPE);
#endif

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
				ret = pkgmgrinfo_pkginfo_compare_app_cert_info(caller, appid, &compare_result);
				if (ret != PMINFO_R_OK) {
					pid = -1;
					_E("compare app cert info failed : %d", ret);
					if(cmd == APP_START_ASYNC)
						close(fd);
					else
						__real_send(fd, pid);
					traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
					return pid;
				}
				if(compare_result != PMINFO_CERT_COMPARE_MATCH) {
					pid = -EILLEGALACCESS;
					if(cmd == APP_START_ASYNC)
						close(fd);
					else
						__real_send(fd, pid);
					traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
					return pid;
				}
			}
		}
	}

	if(operation && caller_ai) {
		ret = __check_app_control_privilege(operation, caller_pid, caller_ai);
		if (ret < 0) {
			if (cmd == APP_START_ASYNC)
				close(fd);
			else
				__real_send(fd, ret);
			traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
			return ret;
		}
	}

	if(__check_mode(ai) < 0) {
		pid = -EREJECTED;
		if(cmd == APP_START_ASYNC)
			close(fd);
		else
			__real_send(fd, pid);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		return pid;
	}

	pkgmgrinfo_client_request_enable_external_pkg((char *)pkgid);

	if (component_type && (strncmp(component_type, APP_TYPE_UI, strlen(APP_TYPE_UI)) == 0
		|| strncmp(component_type, APP_TYPE_WATCH, strlen(APP_TYPE_WATCH)) == 0
		|| strncmp(component_type, APP_TYPE_WIDGET, strlen(APP_TYPE_WIDGET)) == 0 )) {
		gboolean new_process = FALSE;

		multiple = appinfo_get_value(ai, AIT_MULTI);
		if (!multiple || strncmp(multiple, "false", 5) == 0) {
			pid = _status_app_is_running_v2(appid);
		} else if (operation != NULL && strncmp(operation, "http://tizen.org/appcontrol/operation/view", 512) == 0){
			old_caller = _status_get_caller_by_appid(appid);
			if(old_caller && caller) {
				if(strncmp(old_caller, caller, MAX_PACKAGE_STR_SIZE) == 0) {
					pid = _status_app_is_running_v2(appid);
				}
			}
		}

		if (strncmp(component_type, APP_TYPE_UI, strlen(APP_TYPE_UI)) == 0) {
			if (app_group_is_group_app(kb)) {
				pid = -1;
				is_group_app = TRUE;
			}

			int st = -1;

			if (pid > 0)
				st = _status_get_app_info_status(pid);

			if (pid == -1 || st == STATUS_DYING) {
				int found_pid = -1;
				int found_lpid = -1;

				if (app_group_find_singleton(appid, &found_pid, &found_lpid) == 0) {
					pid = found_pid;
					new_process = FALSE;
				} else {
					new_process = TRUE;
				}

				if (app_group_can_start_app(appid, kb, &can_attach, &lpid, &launch_mode) != 0 ) {
					_E("can't make group info");
					pid = -EILLEGALACCESS;
					if (cmd == APP_START_ASYNC)
						close(fd);
					else
						__real_send(fd, pid);
					traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
					return pid;
				}

				if (can_attach && lpid == found_lpid) {
					_E("can't launch singleton app in the same group");
					pid = -EILLEGALACCESS;
					if (cmd == APP_START_ASYNC)
						close(fd);
					else
						__real_send(fd, pid);
					traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
					return pid;
				}

				if (found_pid != -1)
					app_group_clear_top(found_pid);
			}

			if (pid == -1 && can_attach)
				pid = app_group_find_pid_from_recycle_bin(appid);
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
				traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
				return -1;
			}
		}
#endif

		if(caller) {
#ifdef _APPFW_FEATURE_AMD_KEY
			if (caller_component_type && strncmp(caller_component_type, APP_TYPE_UI, strlen(APP_TYPE_UI)) == 0) {
				Ecore_X_Window in_win;
				in_win = _input_window_get();
				if(in_win) {
					ret = ecore_x_pointer_grab(in_win);
					_D("win(%x) ecore_x_pointer_grab(%d)", in_win, ret);
				}
				if(_key_grab(KEY_BACK, EXCLUSIVE_GRAB) < 0) {
					_W("back key grab error");
				} else {
					_D("back key grab");
				}
			}
#endif
		}

		if (__grant_temporary_permission(caller_pid, appid, kb,
			&caller_exec_label, &callee_exec_label, &paths) == 0)
			grant_permission = 1;
		status = _status_get_app_info_status(pid);
		if (pid > 0 && status != STATUS_DYING) {
			if (caller_pid == pid) {
				SECURE_LOGD("caller process & callee process is same.[%s:%d]", appid, pid);
				pid = -ELOCALLAUNCH_ID;
			} else {
				if(strncmp(pkg_type, "wgt", 3) == 0) {
					__pre_launching_processing(appid);
				}

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
			strncpy(log_status, "RESUMING", strlen("RESUMING"));
#endif

				proc_group_change_status(PROC_CGROUP_SET_RESUME_REQUEST, pid, (char *)appid);

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

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
			strncpy(log_status, "LAUNCHING", strlen("LAUNCHING"));
#endif

			// 2.4 bg categorized ui app || watch || widget -> bg allowed (2.3 ui app -> not allowed)
			prelaunch_attribute = __get_prelaunch_attribute(ai);
			if ((strncmp(component_type, APP_TYPE_UI, sizeof(APP_TYPE_UI)) == 0
				&& (prelaunch_attribute & RESOURCED_ALLOWED_BG_ATTRIBUTE))
					|| (strncmp(component_type, APP_TYPE_WATCH, sizeof(APP_TYPE_WATCH)) == 0)
					|| (strncmp(component_type, APP_TYPE_WIDGET, sizeof(APP_TYPE_WIDGET)) == 0)) {
				_D("[__SUSPEND__] allowed background, appid: %s", appid);
				bundle_add(kb, AUL_K_ALLOWED_BG, "ALLOWED_BG");
			}

			__send_proc_prelaunch_signal(appid, pkgid, prelaunch_attribute);

#ifdef _APPFW_FEATURE_FAKE_EFFECT
			fake_effect = bundle_get_val(kb, "__FAKE_EFFECT__");
#endif

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

#ifdef _APPFW_FEATURE_FAKE_EFFECT
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
			vconf_get_int(VCONFKEY_AMD_EFFECT_IMAGE_ENABLE, &effect_mode);
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
				const char *portraitimg = NULL;
				const char *landscapeimg = NULL;
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
				const char *effectimg_type = NULL;
#endif
				const char *indicator = NULL;
				int screen_mode = 0;
				int rotate_allowed = 0;
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
#endif /* _APPFW_FEATURE_FAKE_EFFECT */

#ifdef _APPFW_FEATURE_DEBUG_LAUNCHPAD
			if (bundle_get_type(kb, AUL_K_SDK) != BUNDLE_TYPE_NONE) {
				pad_pid = DEBUG_LAUNCHPAD_PID;
			} else if (strncmp(pkg_type, "wgt", 3) == 0) {
				pad_pid = WEB_LAUNCHPAD_PID;
			}
#else
			if (strncmp(pkg_type, "wgt", 3) == 0) {
				pad_pid = WEB_LAUNCHPAD_PID;
			}
#endif
#ifdef _APPFW_FEATURE_PROCESS_POOL
			else {
				const char *process_pool = appinfo_get_value(ai, AIT_POOL);
				_D("process_pool: %s", process_pool);

				const char *hwacc = appinfo_get_value(ai, AIT_HWACC);
				_D("h/w acceleration: %s", hwacc);

				SECURE_LOGD("appid: %s", appid);

				pad_pid = PROCESS_POOL_LAUNCHPAD_PID;
				char pad_sock[UNIX_PATH_MAX] = { 0, };
				snprintf(pad_sock, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, pad_pid);
				if (access(pad_sock, F_OK) != 0)
				{
					_W("Sending to legacy launchpad because process-pool launchpad is not initialized.");
					pad_pid = NO_LAUNCHPAD_PID;
				}
			}
#endif //_APPFW_FEATURE_PROCESS_POOL
			_W("pad pid(%d)", pad_pid);
			__set_appinfo_for_launchpad(ai, kb);
			if (pad_pid == NO_LAUNCHPAD_PID)
			{
				pid = start_process(appid, app_path, kb);
			}
			else
			{
				pid = app_send_cmd(pad_pid, cmd, kb);
				if (pid == AUL_R_ENOLAUNCHPAD && pad_pid == PROCESS_POOL_LAUNCHPAD_PID) {
					_W("Launch with legacy way");
					pad_pid = NO_LAUNCHPAD_PID;
					pid = start_process(appid, app_path, kb);
				}
			}
			if(pid == AUL_R_ECOMM) {
				pid = -ENOLAUNCHPAD;
			}
			aul_send_app_launch_request_signal(pid, appid, pkgid, component_type);
			snprintf(trm_buf, MAX_PACKAGE_STR_SIZE, "appinfo_launch:%s[PID]%d", appid, pid);
			__trm_app_info_send_socket(trm_buf);
		}
		if(pid < 0) {
#ifdef _APPFW_FEATURE_AMD_KEY
			if(_input_window_get() != 0)
				ecore_x_pointer_ungrab();
			_D("pid(%d) ecore_x_pointer_ungrab", pid);
			if(_key_ungrab(KEY_BACK) < 0) {
				_W("back key ungrab error");
			} else {
				_D("back key ungrab");
			}
#endif
		} else {
			if (new_process) {
				_D("add app group info");
				app_group_start_app(pid, kb, lpid, can_attach, launch_mode);
			} else if (cmd == APP_START
					|| cmd == APP_START_RES
					|| cmd == APP_START_ASYNC
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
					|| cmd == APP_START_MULTI_INSTANCE
#endif
				 ) {
				app_group_restart_app(pid, kb);
			}
#ifdef _APPFW_FEATURE_AMD_KEY
			grab_timer_id = g_timeout_add(1000, __grab_timeout_handler, (void *)pid);
#endif
		}
	}
	else if (component_type && strncmp(component_type, APP_TYPE_SERVICE, sizeof(APP_TYPE_SERVICE)) == 0) {
#ifdef _APPFW_FEATURE_PRIVATE_SERVICE
		const char *caller_appid = _status_app_get_appid_bypid(caller_pid);

		if (caller_appid) {
			const struct appinfo *ai = NULL;
			const char *caller_pkgid = NULL;
			const char *pkgid = NULL;

			ai = appinfo_find(_laf, appid);
			pkgid = appinfo_get_value(ai, AIT_PKGID);
			ai = appinfo_find(_laf, caller_appid);
			caller_pkgid = appinfo_get_value(ai, AIT_PKGID);

			if (caller_pkgid && pkgid && strcmp(caller_pkgid, pkgid) != 0) {
				const char *launch_type = bundle_get_val(kb, OSP_K_LAUNCH_TYPE);

				if (launch_type == NULL || strcmp(launch_type, OSP_V_LAUNCH_TYPE_DATACONTROL) != 0) {
					const char *v = appinfo_get_value(ai, AIT_VISIBILITY);
					char num[256] = { 0, };

					if (v == NULL) {
						int vi_num = 0;

						if (__get_visibility_from_cert_svc(caller_pkgid, &vi_num) == 0) {
							snprintf(num, 255, "%d", vi_num);
							appinfo_set_value((struct appinfo*)ai, AIT_VISIBILITY, num);
							v = num;
						} else
							_E("Failed to get visibility");
					}

					if (v) {
						int visibility = atoi(v);
						if (!(visibility & CERT_SVC_VISIBILITY_PLATFORM)) {
							_E("Couldn't launch service app in other packages");
							__real_send(fd, -EREJECTED);
							traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
							return -EREJECTED;
						}
					}
				}
			}
		}
#endif
		pid = _status_app_is_running_v2(appid);

		prelaunch_attribute = __get_prelaunch_attribute(ai);

		// 2.4 bg-categorized svc app || 2.3 svc app -> bg allowed
		if ((prelaunch_attribute & RESOURCED_ALLOWED_BG_ATTRIBUTE)
				|| !(prelaunch_attribute & RESOURCED_API_VER_2_4_ATTRIBUTE)) {
			_D("[__SUSPEND__] allowed backgroudn, appid: %s", appid);
			bundle_add(kb, AUL_K_ALLOWED_BG, "ALLOWED_BG");
			bg_allowed = true;
		}

		if (__grant_temporary_permission(caller_pid, appid, kb,
			&caller_exec_label, &callee_exec_label, &paths) == 0)
			grant_permission = 1;

		if (pid > 0) {
#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
			strncpy(log_status, "RESUMING", strlen("RESUMING"));
#endif
			aul_send_app_resume_request_signal(pid, appid, pkgid, APP_TYPE_SERVICE);

			if (!bg_allowed)
				__prepare_to_wake_services(pid);

			if ((ret = __nofork_processing(cmd, pid, kb, fd)) < 0) {
				pid = ret;
			}
		} else if (cmd != APP_RESUME) {
#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
			strncpy(log_status, "LAUNCHING", strlen("LAUNCHING"));
#endif

			__send_proc_prelaunch_signal(appid, pkgid, prelaunch_attribute);

#ifdef _APPFW_FEATURE_DEBUG_LAUNCHPAD
			if (bundle_get_type(kb, AUL_K_SDK) != BUNDLE_TYPE_NONE) {
				SECURE_LOGD("The svcapp(%s) is launched by debug-launchpad", appid);
				__set_appinfo_for_launchpad(ai, kb);
				pid = app_send_cmd(DEBUG_LAUNCHPAD_PID, cmd, kb);
				if (pid == AUL_R_ECOMM) {
					pid = -ENOLAUNCHPAD;
				}
			} else {
				pid = start_process(appid, app_path, kb);
			}
#else
			pid = start_process(appid, app_path, kb);
#endif
			aul_send_app_launch_request_signal(pid, appid, pkgid, component_type);
		}

		if (bg_allowed) {
			g_idle_add(__check_service_only, (gpointer)pid);
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

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
	_status_log_save(log_status, appid);
#endif

	if(pid > 0) {
		_status_add_app_info_list(appid, app_path, caller, pid, pad_pid, is_group_app);
		_status_update_app_info_caller_pid(pid, caller_pid);
		if (grant_permission) {
			__add_shared_info(pid, caller_exec_label, callee_exec_label, paths);
			if (caller_exec_label) {
				free(caller_exec_label);
				caller_exec_label = NULL;
			}
			if (callee_exec_label) {
				free(callee_exec_label);
				callee_exec_label = NULL;
			}
		}

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
		snprintf(log_status, AUL_PR_NAME, "SUCCESS: %d", pid);
		_status_log_save(log_status, appid);
#endif

#ifdef _APPFW_FEATURE_APP_CHECKER
		pkg_type = appinfo_get_value(ai, AIT_TYPE);
		if (!pkg_type)
			return -1;

		ret = ac_server_check_launch_privilege(appid, pkg_type, pid);
		if (ret != AC_R_ERROR) {
			traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
			return pid;
		} else {
			traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
			return -1;
		}
#endif
	}
#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
	else {
		_status_log_save("FAILURE", appid);
	}
#endif

	traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
	return pid;
}

int __e17_status_handler(int pid, int status, void *data)
{
	if (status == PROC_STATUS_FG) {
#ifdef _APPFW_FEATURE_AMD_KEY
		_D("pid(%d) status(%d)", pid, status);
		if(_input_window_get() != 0)
			ecore_x_pointer_ungrab();
		if(_key_ungrab(KEY_BACK) < 0) {
			_W("back key ungrab error");
		} else {
			_D("back key ungrab");
		}
		g_source_remove(grab_timer_id);
#endif

		_status_update_app_info_list(pid, STATUS_VISIBLE);
	} else if (status == PROC_STATUS_BG) {
		_status_update_app_info_list(pid, STATUS_BG);
	}

	return 0;
}

int _launch_init(struct amdmgr* amd)
{
	int ret = 0;

	_D("_launch_init");

	amd_cmdline = __proc_get_cmdline_bypid(getpid());

	_laf = amd->af;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		_E("dbus_bus_get error");
		return -EBADMSG;
	}

	ret = aul_listen_e17_status_signal(__e17_status_handler, NULL);

	_D("ret : %d", ret);

	__preexec_init(0, NULL);

	return 0;
}

void _set_atom_effect(void)
{
	ATOM_IMAGE_EFFECT = ecore_x_atom_get(atom_name);
}

void __set_appinfo_for_launchpad(const struct appinfo *ai, bundle *kb) {
	int ret;

	_D("Add hwacc, taskmanage, app_path and pkg_type into bundle for sending those to launchpad.");
	ret = bundle_del(kb, AUL_K_HWACC);
	if (ret != BUNDLE_ERROR_NONE)
		_D("bundle_del error: %d", ret);
	ret = bundle_add(kb, AUL_K_HWACC, appinfo_get_value(ai, AIT_HWACC));
	if (ret != BUNDLE_ERROR_NONE)
		_E("failed to set AUL_K_HWACC: ret(%d)", ret);


	bundle_del(kb, AUL_K_TASKMANAGE);
	if (ret != BUNDLE_ERROR_NONE)
		_D("bundle_del error: %d", ret);
	bundle_add(kb, AUL_K_TASKMANAGE, appinfo_get_value(ai, AIT_TASKMANAGE));
	if (ret != BUNDLE_ERROR_NONE)
		_E("failed to set AUL_K_TASKMANAGE: ret(%d)", ret);

	bundle_del(kb, AUL_K_EXEC);
	if (ret != BUNDLE_ERROR_NONE)
		_D("bundle_del error: %d", ret);
	bundle_add(kb, AUL_K_EXEC, appinfo_get_value(ai, AIT_EXEC));
	if (ret != BUNDLE_ERROR_NONE)
		_E("failed to set AUL_K_EXEC: ret(%d)", ret);

	bundle_del(kb, AUL_K_PACKAGETYPE);
	if (ret != BUNDLE_ERROR_NONE)
		_D("bundle_del error: %d", ret);
	bundle_add(kb, AUL_K_PACKAGETYPE, appinfo_get_value(ai, AIT_TYPE));
	if (ret != BUNDLE_ERROR_NONE)
		_E("failed to set AUL_K_PACKAGETYPE: ret(%d)", ret);

	bundle_del(kb, AUL_K_INTERNAL_POOL);
	if (ret != BUNDLE_ERROR_NONE)
		_D("bundle_del error: %d", ret);
	bundle_add(kb, AUL_K_INTERNAL_POOL, appinfo_get_value(ai, AIT_POOL));
	if (ret != BUNDLE_ERROR_NONE)
		_E("failed to set AUL_K_INTERNAL_POOL: ret(%d)", ret);

	bundle_del(kb, AUL_K_PKGID);
	if (ret != BUNDLE_ERROR_NONE)
		_D("bundle_del error: %d", ret);
	bundle_add(kb, AUL_K_PKGID, appinfo_get_value(ai, AIT_PKGID));
	if (ret != BUNDLE_ERROR_NONE)
		_E("failed to set AUL_K_PKGID: ret(%d)", ret);
}
