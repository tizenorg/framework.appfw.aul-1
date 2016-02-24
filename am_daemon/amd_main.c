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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <Ecore_X.h>
#include <Ecore_Input.h>
#include <Ecore.h>
#include <Evas.h>
#include <aul.h>
#include <vconf.h>
#ifdef _APPFW_FEATURE_APP_CHECKER
#include <app-checker-server.h>
#endif
#include <glib.h>
#include <sys/resource.h>
#include <assert.h>
#include <pkgmgr-info.h>
#include <proc_stat.h>

#include "amd_config.h"
#include "simple_util.h"
#include "aul_util.h"
#include "app_sock.h"
#include "amd_appinfo.h"
#include "amd_key.h"
#include "amd_status.h"
#include "amd_launch.h"
#include "amd_request.h"
#include "amd_app_group.h"
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#include "appfw_env.h"
#include "app_signal.h"
#endif


#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
typedef struct _r_app_info_t{
	char pkg_name[MAX_PACKAGE_STR_SIZE];
	int pid;
} r_app_info_t;

GSList *r_app_info_list = NULL;
#endif

gboolean platform_ready = false;
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
int ups_mode = 0;
#endif

typedef struct _window_watch {
	int watch_fd;
	int win_watch_wd;
	Ecore_Fd_Handler *win_watch_ewd;
} _window_watch_t;
static _window_watch_t *win_info_t = NULL;

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
extern DBusConnection *conn;
extern struct appinfomgr *_laf;
#endif

static int window_initialized = 0;

#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
static void __vconf_cb(keynode_t *key, void *data);
#endif
static int __app_dead_handler(int pid, void *data);
static int __init();

extern int _status_init(struct amdmgr* amd);

#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
static int __kill_bg_apps(int limit)
{
	int len;
	int i;
	int n;
	r_app_info_t *info_t = NULL;
	GSList *iter = NULL;

	len = g_slist_length(r_app_info_list);

	n = len - limit;

	if (n<=0) return 0;

	for ( i=0, iter = r_app_info_list; i<n ; i++) {
		info_t = (r_app_info_t *)iter->data;
		aul_send_app_terminate_request_signal(info_t->pid, NULL, NULL, NULL);
		_term_app(info_t->pid, 0);
		iter = g_slist_next(iter);
		r_app_info_list = g_slist_remove(r_app_info_list, info_t);
		free(info_t);
	}

	return 0;
}

static int __remove_item_running_list(int pid)
{
	r_app_info_t *info_t = NULL;
	GSList *iter = NULL;

	for (iter = r_app_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (r_app_info_t *)iter->data;
		if(pid == info_t->pid) {
			r_app_info_list = g_slist_remove(r_app_info_list, info_t);
			free(info_t);
			break;
		}
	}
	return 0;
}

gboolean __add_item_running_list(gpointer user_data)
{

	bool taskmanage;
	pkgmgrinfo_appinfo_h handle = NULL;
	int ret = 0;
	r_app_info_t *info_t = NULL;
	GSList *iter = NULL;
	int found = 0;
	int limit;

	item_pkt_t *item  = (item_pkt_t *)user_data;
	if (item == NULL) {
		return false;
	}

	char* appid = item->appid;
	int pid = item->pid;

	SECURE_LOGD("__add_item_running_list pid: %d", pid);

	if (vconf_get_int(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS, &limit) != 0){
		_E("Unable to get VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS\n");
	}

	if (appid == NULL) {
		return false;
	} else if (strncmp(appid, "org.tizen.cluster-home", 24) == 0) {
		if(limit>0) __kill_bg_apps(limit-1);
		return false;
	}

	SECURE_LOGD("__add_item_running_list appid: %s", appid);

	ret = pkgmgrinfo_appinfo_get_appinfo(appid, &handle);
	if (ret != PMINFO_R_OK) {
		_E("pkgmgrinfo_pkginfo_get_pkginfo with %s failed", appid);
		return false;
	}

	ret = pkgmgrinfo_appinfo_is_taskmanage(handle, &taskmanage);
	if (ret != PMINFO_R_OK) {
		_E("pkgmgrinfo_appinfo_is_taskmanage failed");
		goto END;
	}

	if (taskmanage == false)
		goto END;

	for (iter = r_app_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (r_app_info_t *)iter->data;
		if(pid == info_t->pid) {
			found = 1;
			r_app_info_list = g_slist_remove(r_app_info_list, info_t);
			r_app_info_list = g_slist_append(r_app_info_list, info_t);
			break;
		}
	}

	if(found == 0) {
		info_t = malloc(sizeof(r_app_info_t));
		if (info_t == NULL) {
			_E("out of memory");
			goto END;
		}

		strncpy(info_t->pkg_name, appid, MAX_PACKAGE_STR_SIZE-1);
		info_t->pid = pid;
		r_app_info_list = g_slist_append(r_app_info_list, info_t);
	}

	for (iter = r_app_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (r_app_info_t *)iter->data;
	}

	if(limit>0) __kill_bg_apps(limit);

	for (iter = r_app_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (r_app_info_t *)iter->data;
	}

END:
	pkgmgrinfo_appinfo_destroy_appinfo(handle);
	return false;
}

static void __vconf_cb(keynode_t *key, void *data)
{
	int limit;
	const char *name;

	name = vconf_keynode_get_name(key);
	if( name == NULL ) {
		return;
	}else if ( strcmp(name, VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS) == 0){
		limit = vconf_keynode_get_int(key);
		if(limit>0) __kill_bg_apps(limit);
	}
}
#endif

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
static int __tep_unmount_dbus(char *mnt_path)
{
	DBusMessage *msg;
	msg = dbus_message_new_method_call(TEP_BUS_NAME, TEP_OBJECT_PATH,
	                                   TEP_INTERFACE_NAME, TEP_UNMOUNT_METHOD);
	if (!msg) {
		_E("dbus_message_new_method_call(%s:%s-%s)", TEP_OBJECT_PATH,
		   TEP_INTERFACE_NAME, TEP_UNMOUNT_METHOD);
		return -1;
	}

	if (!dbus_message_append_args(msg,
	                              DBUS_TYPE_STRING, &mnt_path,
	                              DBUS_TYPE_INVALID)) {
		_E("Ran out of memory while constructing args\n");
		dbus_message_unref(msg);
		return -1;
	}

	if (dbus_connection_send(conn, msg, NULL) == FALSE) {
		_E("dbus send error");
		dbus_message_unref(msg);
		return -1;
	}
	dbus_message_unref(msg);
	return 0;
}

static void __send_unmount_request(int pid)
{
	const char *tep_name = NULL;
	const struct appinfo *ai = NULL;
	char *appid = NULL;
	appid = _status_app_get_appid_bypid(pid);
	if (!appid) {
		_E("_status_app_get_appid_bypid : appid not found");
		return;
	}
	ai = appinfo_find(_laf, appid);
	tep_name = appinfo_get_value(ai, AIT_TEP);
	if (tep_name != NULL) {
		char tep_message[PATH_MAX] = {0, };
		const char *installed_storage = NULL;
		char *mnt_path = NULL;
		struct stat link_buf;

		installed_storage  = appinfo_get_value(ai, AIT_STORAGE_TYPE);
		if (installed_storage != NULL) {
			if (strncmp(installed_storage, "internal", 8) == 0) {
				snprintf(tep_message, sizeof(tep_message), "%s%s/res/tep", appfw_env_get_apps_path(), appid);
				mnt_path = strdup(tep_message);
			} else if (strncmp(installed_storage, "external", 8) == 0) {
				snprintf(tep_message, sizeof(tep_message), "%step/tep-access", appfw_env_get_external_storage_path());
				mnt_path = strdup(tep_message);
			}
			if (mnt_path) {
				int ret = __tep_unmount_dbus(mnt_path);
				if (ret < 0) {
					_E("dbus call failed for unmount");
				}
				ret = lstat(mnt_path, &link_buf);
				if (ret == 0) {
					ret = unlink(mnt_path);
					if (ret == 0)
						_D("Symbolic link removed");
					else
						_E("Failed to remove the link");
				}
				free(mnt_path);
			}
		}
	}
}
#endif

static int __app_dead_handler(int pid, void *data)
{
	char trm_buf[MAX_PACKAGE_STR_SIZE];
	char buf[MAX_LOCAL_BUFSZ];

	_I("__app_dead_handler, pid: %d", pid);

	if(pid <= 0)
		return 0;

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	__send_unmount_request(pid);
#endif

	if (app_group_is_leader_pid(pid)) {
		if (app_group_find_second_leader(pid) == -1) {
			app_group_clear_top(pid);
			app_group_set_dead_pid(pid);
			app_group_remove(pid);
		} else
			app_group_remove_leader_pid(pid);
	} else if (app_group_is_sub_app(pid)) {
		if (app_group_can_reroute(pid))
			app_group_reroute(pid);
		else
			app_group_clear_top(pid);
		app_group_set_dead_pid(pid);
		app_group_remove(pid);
	}

	app_group_remove_from_recycle_bin(pid);

	_unregister_key_event(pid);
#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
	__remove_item_running_list(pid);
#endif
	_revoke_temporary_permission(pid);
	_status_remove_app_info_list(pid);
	snprintf(trm_buf, MAX_PACKAGE_STR_SIZE, "appinfo_terminated:[PID]%d", pid);
	__trm_app_info_send_socket(trm_buf);
	aul_send_app_terminated_signal(pid);

	snprintf(buf, MAX_LOCAL_BUFSZ, "%s/%d", AUL_SOCK_PREFIX, pid);
	unlink(buf);

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
	snprintf(buf, MAX_LOCAL_BUFSZ, "%d", pid);
	_status_log_save("TERMINATED", buf);
#endif

	return 0;
}

static void __start_cb(void *user_data,
		const char *filename, const struct appinfo *ai)
{
	/*struct amdmgr *amd = user_data;*/
	const char *componet = NULL;
	int r;

	componet = appinfo_get_value(ai, AIT_COMPTYPE);

	r = appinfo_get_boolean(ai, AIT_ONBOOT);

	if (r == 1 && componet && strncmp(componet, "svcapp", 6) == 0)
	{
		const char *appid = appinfo_get_value(ai, AIT_NAME);
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
		r = appinfo_get_boolean(ai, AIT_PRELOAD);
		if (ups_mode == SETTING_PSMODE_EMERGENCY && r == 0) {
			_W("In UPS mode, skip to launch the servce apps");
			return;
		}
#endif
		if (appid && _status_app_is_running(appid) < 0)
		{
			_W("start service (on-boot) - %s", appid);
			_start_srv(ai);
		}
		else
		{
			_E("service: %s is already running", appid);
		}
	}
}

static void _start_services(struct amdmgr *amd)
{
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	if(vconf_get_int(VCONFKEY_SETAPPL_PSMODE, &ups_mode) < 0)
		_E("vconf_get_int() failed");
#endif

	appinfo_foreach(amd->af, __start_cb, amd);
}

gboolean _get_platform_ready()
{
	return platform_ready;
}

static gboolean __platform_ready_handler(gpointer data)
{
	_E("[Info]__platform_ready_handler");
	platform_ready = true;

	return FALSE;
}

static int __booting_done_handler(int pid, void *data)
{
	_E("[Info]__booting_done_handler, pid: %d", pid);

	_start_services((struct amdmgr*)data);

	guint timer_id = g_timeout_add(60000, __platform_ready_handler, NULL);
	SECURE_LOGW("[Info] timer_id: %u", timer_id);

	return 0;
}

static void __window_init(void)
{
	_W("_window_init");

	ecore_x_init(NULL);
	_set_atom_effect();
#ifndef __i386__
	_key_init();
#endif
	window_initialized = 1;
}

int _window_is_initialized()
{
	return window_initialized;
}

static Eina_Bool _window_cb(void *data, Ecore_Fd_Handler * fd_handler)
{
	int fd;
	char buf[FILENAME_MAX] = {0};
	ssize_t len = 0;
	struct inotify_event* event;

	if (ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_ERROR)) {
		_E("An error has occurred. Stop watching this fd and quit");
		return ECORE_CALLBACK_CANCEL;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);
	if(fd < 0) {
		_E("ecore_main_fd_handler_fd_get error");
		return ECORE_CALLBACK_CANCEL;
	}
	len = read(fd, buf, FILENAME_MAX);
	if (len < 0)
		_E("read failed, error [%s]", strerror(errno));;

	event = (struct inotify_event*) &buf[0];

	if(event)
		_D("filename : %s", event->name);

	if (_status_check_window_ready()) {
		__window_init();
		if (win_info_t) {
			ecore_main_fd_handler_del(win_info_t->win_watch_ewd);
			inotify_rm_watch(win_info_t->watch_fd, win_info_t->win_watch_wd);
			free(win_info_t);
			win_info_t = NULL;
		}
	}

	return ECORE_CALLBACK_RENEW;
}

static void _register_window_init(void)
{
	_W("_register_window_init");

	win_info_t = malloc(sizeof(_window_watch_t));
	if (!win_info_t) {
		_E("Unable to allocate memory. don't init widow\n");
		return;
	}
	win_info_t->watch_fd = inotify_init();
	win_info_t->win_watch_wd = inotify_add_watch(win_info_t->watch_fd, "/tmp", IN_CREATE);
	win_info_t->win_watch_ewd = ecore_main_fd_handler_add(win_info_t->watch_fd,
						    ECORE_FD_READ, _window_cb, NULL, NULL, NULL);
}

static void _window_init(void)
{
	if (_status_check_window_ready())
		__window_init();
	else
		_register_window_init();
}

static int __init()
{
	struct amdmgr amd;
	int ret = 0;

	/* sigprocmask() is used to fetch and/or change the signal mask of the calling thread.
	 * As a result, please make sure that there are not any other threads except for calling thread.
	 * */
	int fd = _signal_block_sigchld();
	assert(fd != -1);

	ecore_init();
	evas_init();
	ecore_event_init();

	_W("ecore init done\n");

	ret = appinfo_init(&amd.af);
	assert(ret == 0);

	ret = _request_init(&amd, fd);
	assert(ret == 0);

	_launch_init(&amd);
	_status_init(&amd);
	_window_init();
	app_group_init();

	_W("AMD init done\n");

#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS, __vconf_cb, NULL) != 0) {
		_E("Unable to register callback for VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS\n");
	}
#endif

	aul_listen_app_dead_signal(__app_dead_handler, NULL);
	aul_listen_booting_done_signal(__booting_done_handler, &amd);

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	int res = setpriority(PRIO_PROCESS, 0, -12);
	if (res == -1)
	{
		_E("Setting process (%d) priority to -12 failed, errno: %d (%s)",
				getpid(), errno, strerror(errno));
	}
#endif
	return 0;
}

gboolean  __amd_ready(gpointer user_data)
{
	_W("AMD ready\n");

	int handle = creat("/tmp/amd_ready", S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	if (handle != -1)
		close(handle);

	return FALSE;
}

int main(int argc, char *argv[])
{
	_W("AMD main()\n");

#ifdef _APPFW_FEATURE_APP_CHECKER
	if (ac_server_initialize() != AC_R_OK){
		_E("ac_server_initialize failed!\n");
		assert(0);
		return -1;
	}
#endif
	if (__init() != 0){
		assert(0);
		_E("AMD Initialization failed!\n");
		return -1;
	}

	g_idle_add(__amd_ready, NULL);

	ecore_main_loop_begin();

	return 0;
}
