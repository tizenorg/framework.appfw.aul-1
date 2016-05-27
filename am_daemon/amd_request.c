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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <poll.h>
#include <aul.h>
#include <glib.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <rua.h>
#include <rua_stat.h>
#include <proc_stat.h>
#include <security-server.h>
#include <vconf.h>
#include <ttrace.h>
#include <Ecore.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <wait.h>
#include <pkgmgr-info.h>

#include "amd_config.h"
#include "simple_util.h"
#include "app_sock.h"
#include "app_signal.h"
#include "aul_util.h"
#include "amd_request.h"
#include "amd_key.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_app_group.h"

#define INHOUSE_UID     5000

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
#define METADATA_MULTI_INSTANCE		"http://developer.samsung.com/tizen/metadata/multiinstance"
#endif

struct appinfomgr *_raf;
static DBusConnection *bus = NULL;
static sigset_t oldmask;
#ifdef _APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL
char *home_appid = NULL;
#endif

struct restart_info {
	char *appid;
	int count;
	Ecore_Timer *timer;
};

GHashTable *restart_tbl;

static int __send_result_to_client(int fd, int res);
static gboolean __request_handler(gpointer data);

// TODO: Replace with pkgmgr-info header
int pkgmgrinfo_updateinfo_check_update(const char* pkgid);

static int __send_result_data(int fd, int cmd, unsigned char *kb_data, int datalen)
{
	int len;
	int ret;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (datalen > AUL_SOCK_MAXBUFF - 8) {
		_E("datalen > AUL_SOCK_MAXBUFF\n");
		return -EINVAL;
	}

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, datalen);

	if ((len = send(fd, pkt, datalen + 8, MSG_NOSIGNAL)) != datalen + 8) {
		_E("sendto() failed - %d %d (errno %d)", len, datalen + 8, errno);
		if(len > 0) {
			while (len != datalen + 8) {
				ret = send(fd, &pkt->data[len-8], datalen + 8 - len, MSG_NOSIGNAL);
				if (ret < 0) {
					_E("second sendto() failed - %d %d (errno %d)", ret, datalen + 8, errno);
					close(fd);
					if (pkt) {
						free(pkt);
						pkt = NULL;
					}
					return -ECOMM;
				}
				len += ret;
				_D("sendto() len - %d %d", len, datalen + 8);
			}
		} else {
			close(fd);
			if (pkt) {
				free(pkt);
				pkt = NULL;
			}
			return -ECOMM;
		}
	}
	if (pkt) {
		free(pkt);
		pkt = NULL;
	}

	close(fd);
	return res;
}

static int __send_result_to_client(int fd, int res)
{
	if (fd < 0)
		return -1;

	_W("__send_result_to_client, pid: %d", res);

	if (send(fd, &res, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
		}

		_E("send fail to client");
	}
	close(fd);
	return 0;
}

static void __real_send(int clifd, int ret)
{
	if(clifd < 0)
		return;

	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
		}
		_E("send fail to client");
	}

	close(clifd);
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

static int __foward_cmd(int cmd, bundle *kb, int cr_pid)
{
	int pid;
	int pgid;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	int datalen;
	bundle_raw *kb_data;
	int res;

	if ((pid = __get_caller_pid(kb)) < 0)
	{
		return AUL_R_ERROR;
	}

	pgid = getpgid(cr_pid);
	if(pgid > 0) {
		snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", pgid);
		bundle_del(kb, AUL_K_CALLEE_PID);
		bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);
	}

	_W("__forward_cmd: %d %d", cr_pid, pgid);

	bundle_encode(kb, &kb_data, &datalen);
	if ((res = __app_send_raw_with_noreply(pid, cmd, kb_data, datalen)) < 0)
		res = AUL_R_ERROR;

	free(kb_data);

	return res;
}

static int __app_process_by_pid(int cmd,
	const char *pkg_name, struct ucred *cr, int clifd)
{
	int pid;
	int ret = -1;
	int dummy;
	char *appid = NULL;
	const char *pkgid = NULL;
	const char *type = NULL;
	const struct appinfo *ai = NULL;

	if (pkg_name == NULL)
		return -1;

	pid = atoi(pkg_name);
	if (pid <= 1) {
		_E("invalid pid");
		return -1;
	}

	/* check whether app process is dead or not */
	char buf[1024];
	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	if (access(buf, F_OK) != 0) {
		_E("pid(%d) is dead. cmd(%d) is canceled", pid, cmd);
		__real_send(clifd, -ECOMM);
		return -ECOMM;
	}

	if (_status_get_app_info_status(pid) == -1) {
		char buf[512];
		if (_status_get_pkgname_bypid(pid, buf, 512) == -1) {
			_E("request for unknown pid. It might not be a pid of app: %d", pid);
			__real_send(clifd, -1);
			return -1;
		}
	}

	appid = _status_app_get_appid_bypid(pid);
	ai = appinfo_find(_raf, appid);
	pkgid = appinfo_get_value(ai, AIT_PKGID);
	type = appinfo_get_value(ai, AIT_COMPTYPE);

	if (cmd == APP_RESUME_BY_PID)
		aul_send_app_resume_request_signal(pid, appid, pkgid, type);
	else
		aul_send_app_terminate_request_signal(pid, appid, pkgid, type);

	SECURE_LOGD("__app_process_by_pid, pid: %d, ", pid);
	switch (cmd) {
	case APP_RESUME_BY_PID:
		ret = _resume_app(pid, clifd);
		break;
	case APP_TERM_BY_PID:
	case APP_TERM_BY_PID_WITHOUT_RESTART:
		ret = _term_app(pid, clifd);
		break;
	case APP_TERM_BGAPP_BY_PID:
		ret = _term_bgapp(pid, clifd);
		break;
	case APP_KILL_BY_PID:
		if ((ret = _send_to_sigkill(pid)) < 0)
			_E("fail to killing - %d\n", pid);
		__real_send(clifd, ret);
		break;
	case APP_TERM_REQ_BY_PID:
		ret = _term_req_app(pid, clifd);
		break;
	case APP_TERM_BY_PID_ASYNC:
		if ((ret = __app_send_raw_with_noreply(pid, cmd, (unsigned char *)&dummy, sizeof(int))) < 0) {
			_D("terminate req packet send error");
		}
		__real_send(clifd, ret);
		break;
	case APP_PAUSE_BY_PID:
		ret = _pause_app(pid, clifd);
		break;
	default:
		break;
	}

	return ret;
}

#ifdef _APPFW_FEATURE_EFFECTIVE_APPID
static void __set_effective_appid(bundle *kb)
{
	const struct appinfo *ai;
	const struct appinfo *effective_ai;
	char *appid;
	const char *effective_appid;

	appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
	if (appid) {
		ai = appinfo_find(_raf, appid);
		if (ai == NULL)
			return;

		effective_appid = appinfo_get_value(ai, AIT_EFFECTIVE_APPID);
		if (effective_appid) {
			const char *pkgid;
			const char *effective_pkgid;
			effective_ai = appinfo_find(_raf, effective_appid);
			if (effective_ai == NULL)
				return;

			pkgid = appinfo_get_value(ai, AIT_PKGID);
			effective_pkgid = appinfo_get_value(effective_ai, AIT_PKGID);
			if (pkgid && effective_pkgid && strcmp(pkgid, effective_pkgid) == 0) {
				_D("use effective appid instead of the real appid");
				bundle_del(kb, AUL_K_PKG_NAME);
				bundle_add(kb, AUL_K_PKG_NAME, effective_appid);
			}
		}
	}
}
#endif

static gboolean __add_history_handler(gpointer user_data)
{
	struct rua_rec rec;
	int ret;
	bundle *kb = NULL;
	char *appid = NULL;
	char *app_path = NULL;
	char *stat_caller = NULL;
	char *stat_tag = NULL;
	struct appinfo *ai;

	app_pkt_t *pkt = (app_pkt_t *)user_data;

	if (!pkt)
		return FALSE;
	kb = bundle_decode(pkt->data, pkt->len);

	if (!app_group_is_group_app(kb)) {

#ifdef _APPFW_FEATURE_EFFECTIVE_APPID
		__set_effective_appid(kb);
#endif
		appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);

		ai = (struct appinfo *)appinfo_find(_raf, appid);
		app_path = (char *)appinfo_get_value(ai, AIT_EXEC);

		memset((void *)&rec, 0, sizeof(rec));

		rec.pkg_name = appid;
		rec.app_path = app_path;

		if(pkt->len > 0) {
			rec.arg = (char *)pkt->data;
		}

		SECURE_LOGD("add rua history %s %s", rec.pkg_name, rec.app_path);

		ret = rua_add_history(&rec);
		if (ret == -1)
			_D("rua add history error");
	}

	stat_caller = (char *)bundle_get_val(kb, AUL_SVC_K_RUA_STAT_CALLER);
	stat_tag = (char *)bundle_get_val(kb, AUL_SVC_K_RUA_STAT_TAG);

	if (stat_caller != NULL && stat_tag != NULL) {
		SECURE_LOGD("rua_stat_caller: %s, rua_stat_tag: %s", stat_caller, stat_tag);
		rua_stat_update(stat_caller, stat_tag);
	}

	if (kb != NULL)
		bundle_free(kb);
	free(pkt);

	return FALSE;
}

static int __get_pid_cb(void *user_data, const char *group, pid_t pid)
{
	int *sz = user_data;

	_D("%s: %d : %d", *sz, pid);
	*sz = 1; /* 1 is enough */

	return -1; /* stop the iteration */
}

int _release_srv(const char *appid)
{
	int r;
	const struct appinfo *ai;

	ai = (struct appinfo *)appinfo_find(_raf, appid);
	if (!ai) {
		_E("appid not found");
		SECURE_LOGE("release service: '%s' not found", appid);
		return -1;
	}

	r = appinfo_get_boolean(ai, AIT_RESTART);
	if (r == 1) {
		_W("Auto restart");
		SECURE_LOGD("Auto restart set: '%s'", appid);
		return _start_srv(ai);
	}

	return 0;
}

static Eina_Bool __restart_timeout_handler(void *data)
{
	struct restart_info *ri = (struct restart_info *)data;

	_D("ri (%x)", ri);
	SECURE_LOGD("appid (%s)", ri->appid);

	g_hash_table_remove(restart_tbl, ri->appid);
	free(ri->appid);
	free(ri);

	return ECORE_CALLBACK_CANCEL;
}

static bool __check_restart(const char *appid)
{
	struct restart_info *ri = NULL;
	//struct appinfo *ai = NULL;

	ri = g_hash_table_lookup(restart_tbl, appid);

	if(!ri) {
		ri = calloc(1, sizeof(*ri));
		if (!ri) {
			_E("create restart info: %s", strerror(errno));
			return true;
		}
		memset(ri, 0, sizeof(struct restart_info));
		ri->appid = strdup(appid);
		ri->count = 1;
		g_hash_table_insert(restart_tbl, ri->appid, ri);

		_D("ri (%x)", ri);
		SECURE_LOGD("appid (%s)", appid);

		ri->timer = ecore_timer_add(10, __restart_timeout_handler, ri);
	} else {
		ri->count++;
		_D("count (%d)", ri->count);
		if(ri->count > 5) {
			/*ai = appinfo_find(_raf, appid);
			if(ai) {
				appinfo_set_value(ai, AIT_STATUS, "norestart");
			}*/
			ecore_timer_del(ri->timer);
			return false;
		}
	}
	return true;
}

#ifdef _APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL
static inline int __send_home_launch_signal(int pid)
{
	DBusMessage *message;

	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
					  AUL_DBUS_SIGNAL_INTERFACE,
					  AUL_DBUS_HOMELAUNCH_SIGNAL);

	if (dbus_message_append_args(message,
				     DBUS_TYPE_UINT32, &pid,
				     DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_W("send a home launch signal");

	return 0;
}
#endif

static inline int __send_app_termination_signal(int dead_pid)
{
	DBusMessage *message;

	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
					  AUL_DBUS_SIGNAL_INTERFACE,
					  AUL_DBUS_APPDEAD_SIGNAL);

	if (dbus_message_append_args(message,
				     DBUS_TYPE_UINT32, &dead_pid,
				     DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_W("send dead signal done");

	return 0;
}

int _send_set_process_group_signal_signal(int owner_pid, int child_pid)
{
	DBusMessage *message;

	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(RESOURCED_PROC_OBJECT,
					  RESOURCED_PROC_INTERFACE,
					  RESOURCED_PROC_GROUP_SIGNAL);

	if (dbus_message_append_args(message,
					 DBUS_TYPE_INT32, &owner_pid,
					 DBUS_TYPE_INT32, &child_pid,
					 DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_W("send set_process_group signal done");

	return 0;
}

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
static char* __get_metadata_value(const char *appid, const char *metadata_key)
{
	int ret = 0;
	pkgmgrinfo_appinfo_h handle;
	char *metadata_value = NULL;
	char *multi_appid = NULL;

	ret = pkgmgrinfo_appinfo_get_appinfo(appid, &handle);
	if (ret != PMINFO_R_OK)
		return NULL;

	ret = pkgmgrinfo_appinfo_get_metadata_value(handle, metadata_key, &metadata_value);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return NULL;
	}

	multi_appid = strdup(metadata_value);

	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return multi_appid;
}

static const char* __check_target_appid(const struct appinfo* ai, const char *appid, const char *multi_appid)
{
	const char* target = NULL;

	// Both apps are running
	if (_status_app_is_running(appid) != -1 && _status_app_is_running(multi_appid) != -1) {
		const char* toggle = appinfo_get_value(ai, AIT_TOGGLE_ORDER);
		int order = atoi(toggle);

		_D("launch a multi-instance app with toggle mode: %d", order);
		switch (order) {
			case 0:
				target = multi_appid;
				appinfo_set_value((struct appinfo *)ai,
					AIT_TOGGLE_ORDER, "1");
				break;

			case 1:
				target = appid;
				appinfo_set_value((struct appinfo *)ai,
					AIT_TOGGLE_ORDER, "0");
				break;

			default:
				break;
		}
	} else {
		// Main app is running
		if (_status_app_is_running(appid) != -1) {
			SECURE_LOGD("Send a request to the running main appid: %s", appid);
			target = appid;
			// Sub app is running
		} else if (_status_app_is_running(multi_appid) != -1) {
			SECURE_LOGD("Send a request to the running sub appid: %s", multi_appid);
			target = multi_appid;
		} else {
			SECURE_LOGD("Both apps are not running, launch a main app - %s", appid);
			target = appid;
		}
	}

	return target;
}
#endif

static void __dispatch_app_group_get_window(int clifd, const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int pid;
	int wid;

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_PID, &buf);
	pid = atoi(buf);
	bundle_free(b);
	wid = app_group_get_window(pid);
	__real_send(clifd, wid);
}

static void __dispatch_app_group_set_window(int clifd, const app_pkt_t *pkt, int pid)
{
	bundle *b;
	char *buf;
	int wid;
	int ret;

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_WID, &buf);
	wid = atoi(buf);
	bundle_free(b);
	ret = app_group_set_window(pid, wid);
	__real_send(clifd, ret);
}

static void __dispatch_app_group_get_fg_flag(int clifd, const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int pid;
	int fg;

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_PID, &buf);
	pid = atoi(buf);
	bundle_free(b);
	fg = app_group_get_fg_flag(pid);
	__real_send(clifd, fg);
}

static void __dispatch_app_group_clear_top(int clifd, int pid)
{
	app_group_clear_top(pid);
	__real_send(clifd, 0);
}

static void __dispatch_app_group_get_leader_pid(int clifd,
		const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int pid;
	int lpid;

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_PID, &buf);
	pid = atoi(buf);
	bundle_free(b);
	lpid = app_group_get_leader_pid(pid);
	__real_send(clifd, lpid);
}

static void __dispatch_app_group_get_leader_pids(int clifd,
		const app_pkt_t *pkt)
{
	int cnt;
	int *pids;
	unsigned char empty[1] = { 0 };

	app_group_get_leader_pids(&cnt, &pids);

	if (pids == NULL || cnt == 0) {
		__send_result_data(clifd, APP_GROUP_GET_LEADER_PIDS, empty, 0);
	} else {
		__send_result_data(clifd, APP_GROUP_GET_LEADER_PIDS,
			(unsigned char *)pids, cnt * sizeof(int));
	}
	if (pids != NULL)
		free(pids);
}

static void __dispatch_app_group_get_idle_pids(int clifd,
		const app_pkt_t *pkt)
{
	int cnt;
	int *pids;
	unsigned char empty[1] = { 0 };

	app_group_get_idle_pids(&cnt, &pids);

	if (pids == NULL || cnt == 0) {
		__send_result_data(clifd, APP_GROUP_GET_IDLE_PIDS, empty, 0);
	} else {
		__send_result_data(clifd, APP_GROUP_GET_IDLE_PIDS,
			(unsigned char *)pids, cnt * sizeof(int));
	}
	if (pids != NULL)
		free(pids);
}

static void __dispatch_app_group_get_group_pids(int clifd, const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int leader_pid;
	int cnt;
	int *pids;
	unsigned char empty[1] = { 0 };

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_LEADER_PID, &buf);
	leader_pid = atoi(buf);
	bundle_free(b);

	app_group_get_group_pids(leader_pid, &cnt, &pids);
	if (pids == NULL || cnt == 0) {
		__send_result_data(clifd, APP_GROUP_GET_GROUP_PIDS, empty, 0);
	} else {
		__send_result_data(clifd, APP_GROUP_GET_GROUP_PIDS,
			(unsigned char *)pids, cnt * sizeof(int));
	}
	if (pids != NULL)
		free(pids);
}

static void __dispatch_app_group_lower(int clifd, int pid)
{
	int ret = 0;

	app_group_lower(pid, &ret);
	__real_send(clifd, ret);
}

static void  __check_host_pid(bundle *kb, struct ucred *cr)
{
	if (cr->pid == 0) {
		SECURE_LOGD("check host pid");

		char *spid = NULL;

		bundle_get_str(kb, AUL_K_HOST_PID, &spid);
		if (spid != NULL) {
			cr->pid = atoi(spid);
			SECURE_LOGD("caller pid was changed by host pid %s", spid);
		}
	}
}

static gboolean __request_handler(gpointer data)
{
	GPollFD *gpollfd = (GPollFD *) data;
	int fd = gpollfd->fd;
	app_pkt_t *pkt;
	int clifd;
	struct ucred cr;
	int *status;
	int ret = -1;
	int free_pkt = 1;
	char *appid = NULL;
	char *term_pid = NULL;
	int pid;
	bundle *kb = NULL;
	const struct appinfo *ai;
	int owner_pid;
	int child_pid;

	traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "AUL:AMD:REQ_HANDLER");
	if ((pkt = __app_recv_raw(fd, &clifd, &cr)) == NULL) {
		_E("recv error");
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		return FALSE;
	}

	kb = bundle_decode(pkt->data, pkt->len);
#ifdef _APPFW_FEATURE_EFFECTIVE_APPID
	__set_effective_appid(kb);
#endif
	_D("__request_handler: %d", pkt->cmd);

	switch (pkt->cmd) {
		case APP_OPEN:
		case APP_RESUME:
		case APP_START:
		case APP_START_RES:
		case APP_START_ASYNC:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::launch", "x");
			if (cr.pid != 0 && ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("launch request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				__check_host_pid(kb, &cr);
				appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
				// Check the multi-instance app
				ai = appinfo_find(_raf, appid);
				if (ai == NULL) {
					_E("no appinfo");
					__real_send(clifd, -ENOAPP);
				} else {
					const char* multi = appinfo_get_value(ai, AIT_MULTI_INSTANCE);
					if( multi && strncmp(multi, "true", strlen("true")) == 0 ) {

						char* multi_appid =__get_metadata_value(appid, METADATA_MULTI_INSTANCE);
						if (multi_appid != NULL)
						{
							SECURE_LOGD("Multi-instance main: %s, sub: %s", appid, multi_appid);
							const char* target_appid = __check_target_appid(ai, appid, multi_appid);

							SECURE_LOGD("launch a target appid: - %s", target_appid);
							ret = _start_app(target_appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
						} else {
							SECURE_LOGD("No multi-instance app information, launch a main appid: - %s", appid);
							ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
						}

						free(multi_appid);
					}
					else
					{
						SECURE_LOGD("launch a single-instance appid: %s", appid);
						ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
					}
				}
#else
				ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
#endif

				if (ret > 0 && bundle_get_type(kb, AUL_K_PRELAUCHING) == BUNDLE_TYPE_NONE) {
#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
					if (!app_group_is_group_app(kb)) {
						item_pkt_t *item = g_malloc0(sizeof(item_pkt_t));
						item->pid = ret;
						strncpy(item->appid, appid, 511);
						__add_item_running_list(item);
						g_free(item);
					}
#endif
#ifdef _APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL
					if (home_appid && strncmp(appid, home_appid, strlen(appid)) == 0)
						__send_home_launch_signal(ret);
#endif
					g_timeout_add(1500, __add_history_handler, pkt);
					free_pkt = 0;
				}

				if (kb != NULL)
					bundle_free(kb), kb = NULL;
			}
			break;
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
		case APP_START_MULTI_INSTANCE:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::launch", "x");
			if (cr.pid != 0 && ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("launch request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);

				SECURE_LOGD("launch a multi-instance appid: %s", appid);
				ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
			}

			if (ret > 0) {
#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
				if (!app_group_is_group_app(kb)) {
					item_pkt_t *item = g_malloc0(sizeof(item_pkt_t));
					item->pid = ret;
					strncpy(item->appid, appid, 511);
					__add_item_running_list(item);
					g_free(item);
				}
#endif
#ifdef _APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL
				if (home_appid && strncmp(appid, home_appid, strlen(appid)) == 0)
					__send_home_launch_signal(ret);
#endif
				g_timeout_add(1500, __add_history_handler, pkt);
				free_pkt = 0;
			}

			if (kb != NULL)
				bundle_free(kb), kb = NULL;

			break;
#endif
		case APP_RESULT:
		case APP_CANCEL:
			ret = __foward_cmd(pkt->cmd, kb, cr.pid);
			close(clifd);
			break;
		case APP_PAUSE:
			appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
			ret = _status_app_is_running_v2_cached(appid);
			if (ret > 0) {
				_pause_app(ret, clifd);
			} else {
				_E("%s is not running", appid);
				close(clifd);
			}
			break;
		case APP_RESUME_BY_PID:
		case APP_PAUSE_BY_PID:
		case APP_TERM_REQ_BY_PID:
			appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
			ret = __app_process_by_pid(pkt->cmd, appid, &cr, clifd);
			break;
		case APP_TERM_BY_PID_WITHOUT_RESTART:
		case APP_TERM_BY_PID_ASYNC:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::terminate", "x");
			if (cr.pid != 0 && ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("terminate request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				term_pid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
				appid = _status_app_get_appid_bypid(atoi(term_pid));
				ai = appinfo_find(_raf, appid);
				if (ai) {
					appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "norestart");
					ret = __app_process_by_pid(pkt->cmd, term_pid, &cr, clifd);
				} else {
					ret = -1;
					__send_result_to_client(clifd, ret);
				}
			}
			break;
		case APP_TERM_BY_PID:
		case APP_KILL_BY_PID:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::terminate", "x");
			if (cr.pid != 0 && ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("terminate request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
				ret = __app_process_by_pid(pkt->cmd, appid, &cr, clifd);
			}
			break;
		case APP_TERM_BGAPP_BY_PID:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::terminatebgapp", "x");
			if (cr.pid != 0 && ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("terminate request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
				ret = __app_process_by_pid(pkt->cmd, appid, &cr, clifd);
			}
			break;
		case APP_RUNNING_INFO:
			_status_send_running_appinfo_v2(clifd);
			break;
		case APP_RUNNING_INFO_MEMORY:
			_status_send_running_appinfo(clifd);
			break;
		case APP_IS_RUNNING:
			appid = malloc(MAX_PACKAGE_STR_SIZE);
			if (appid == NULL) {
				_E("Failed to allocate memory");
				__send_result_to_client(clifd, -1);
				break;
			}
			strncpy(appid, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
			ret = _status_app_is_running_v2_cached(appid);
			SECURE_LOGD("APP_IS_RUNNING : %s : %d",appid, ret);
			if (ret > 0 && _status_get_app_info_status(ret) == STATUS_DYING) {
				SECURE_LOGD("APP_IS_RUNNING: %d is dying", ret);
				ret = -1;
			}
			__send_result_to_client(clifd, ret);
			free(appid);
			break;
		case APP_GET_APPID_BYPID:
			memcpy(&pid, pkt->data, sizeof(int));
			ret = _status_get_appid_bypid(clifd, pid);
			_D("APP_GET_APPID_BYPID : %d : %d", pid, ret);
			break;
		case APP_GET_PKGID_BYPID:
			memcpy(&pid, pkt->data, sizeof(int));
			ret = _status_get_pkgid_bypid(clifd, pid);
			_D("APP_GET_PKGID_BYPID : %d : %d", pid, ret);
			break;
		case APP_KEY_RESERVE:
			ret = _register_key_event(cr.pid);
			__send_result_to_client(clifd, ret);
			break;
		case APP_KEY_RELEASE:
			ret = _unregister_key_event(cr.pid);
			__send_result_to_client(clifd, ret);
			break;
		case APP_STATUS_UPDATE:
			status = (int *)pkt->data;
			_W("app status : %d", *status);
			if(*status == STATUS_NORESTART) {
				appid = _status_app_get_appid_bypid(cr.pid);
				ai = appinfo_find(_raf, appid);
				appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "norestart");
			} else {
				ret = _status_update_app_info_list(cr.pid, *status, FALSE);
			}
			close(clifd);
			break;
		case APP_GET_STATUS:
			memcpy(&pid, pkt->data, sizeof(int));
			ret = _status_get_app_info_status(pid);
			__send_result_to_client(clifd, ret);
			break;

		case APP_RUNNING_LIST_UPDATE:
			/*appid = (char *)bundle_get_val(kb, AUL_K_APPID);
			  app_path = (char *)bundle_get_val(kb, AUL_K_EXEC);
			  tmp_pid = (char *)bundle_get_val(kb, AUL_K_PID);
			  pid = atoi(tmp_pid);
			  ret = _status_add_app_info_list(appid, app_path, pid);*/
			ret = 0;
			__send_result_to_client(clifd, ret);
			break;

		case APP_GROUP_GET_WINDOW:
			__dispatch_app_group_get_window(clifd, pkt);
			break;

		case APP_GROUP_SET_WINDOW:
			__dispatch_app_group_set_window(clifd, pkt, cr.pid);
			break;

		case APP_GROUP_GET_FG:
			__dispatch_app_group_get_fg_flag(clifd, pkt);
			break;

		case APP_GROUP_GET_LEADER_PIDS:
			__dispatch_app_group_get_leader_pids(clifd, pkt);
			break;

		case APP_GROUP_GET_GROUP_PIDS:
			__dispatch_app_group_get_group_pids(clifd, pkt);
			break;

		case APP_GROUP_CLEAR_TOP:
			__dispatch_app_group_clear_top(clifd, cr.pid);
			break;

		case APP_GROUP_GET_LEADER_PID:
			__dispatch_app_group_get_leader_pid(clifd, pkt);
			break;

		case APP_GROUP_LOWER:
			__dispatch_app_group_lower(clifd, cr.pid);
			break;

		case APP_GROUP_GET_IDLE_PIDS:
			__dispatch_app_group_get_idle_pids(clifd, pkt);
			break;

		case APP_GET_CMDLINE:
			memcpy(&pid, pkt->data, sizeof(int));
			ret = _status_get_cmdline(clifd, pid);
			_D("APP_GET_CMDLINE : %d : %d", pid, ret);
			break;

		case APP_GET_PID:
			appid = (char *)malloc(MAX_PACKAGE_STR_SIZE);
			if (appid == NULL) {
				_E("failed to allocate appid");
				__send_result_to_client(clifd, -1);
				break;
			}
			strncpy(appid, (const char *)pkt->data, MAX_PACKAGE_STR_SIZE - 1);
			ret = _status_app_is_running_v2_cached(appid);
			SECURE_LOGD("APP_GET_PID: %s : %d", appid, ret);
			__send_result_to_client(clifd, ret);
			free(appid);
			break;

		case APP_GET_PID_CACHE:
			appid = (char *)malloc(MAX_PACKAGE_STR_SIZE);
			if (appid == NULL) {
				_E("failed to allocate appid");
				__send_result_to_client(clifd, -1);
				break;
			}
			strncpy(appid, (const char *)pkt->data, MAX_PACKAGE_STR_SIZE - 1);
			ret = _status_app_is_running_from_cache(appid);
			SECURE_LOGD("APP_GET_PID_CACHE: %s : %d", appid, ret);
			__send_result_to_client(clifd, ret);
			free(appid);
			break;

		case APP_GET_LAST_CALLER_PID:
			memcpy(&pid, pkt->data, sizeof(int));
			ret = _status_get_app_info_last_caller_pid(pid);
			SECURE_LOGD("APP_GET_LAST_CALLER_PID: %d : %d", pid, ret);
			__send_result_to_client(clifd, ret);
			break;
		case APP_SET_PROCESS_GROUP:
			owner_pid = atoi(bundle_get_val(kb, AUL_K_OWNER_PID));
			child_pid = atoi(bundle_get_val(kb, AUL_K_CHILD_PID));
			ret = _send_set_process_group_signal_signal(owner_pid, child_pid);
			if (kb != NULL)
				bundle_free(kb), kb = NULL;
			__send_result_to_client(clifd, ret);
			break;
		case APP_GET_GROUP_INFO:
			_status_send_group_info(clifd);
			break;
		default:
			_E("no support packet");
			close(clifd);
	}

	if (free_pkt)
		free(pkt);

	if (kb != NULL)
		bundle_free(kb), kb = NULL;

	traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
	return TRUE;
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

#ifdef _APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL
static void __home_appid_vconf_cb(keynode_t *key, void *data)
{
	char *tmpstr;

	tmpstr = vconf_keynode_get_str(key);
	if (tmpstr == NULL) {
		return;
	}

	if (home_appid) {
		free(home_appid);
	}
	home_appid = strdup(tmpstr);
}
#endif

static int __signal_get_sigchld_fd(sigset_t mask)
{
	int sfd;

	sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);

	if (sfd == -1) {
		_E("failed to create signalfd for SIGCHLD");
		return -1;
	}

	return sfd;
}

static void __release_app(int pid)
{
	const char *pkg_status;
	const char *appid = NULL;
	const struct appinfo *ai = NULL;

	appid = _status_app_get_appid_bypid(pid);
	ai = appinfo_find(_raf, appid);
	pkg_status = appinfo_get_value(ai, AIT_STATUS);
	SECURE_LOGI("appid: %s", appid);
	if (ai && pkg_status && strncmp(pkg_status, "blocking", 8) == 0) {
		appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "restart");
	} else if (ai && pkg_status && strncmp(pkg_status, "norestart", 9) == 0) {
		appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "installed");
	} else {
		if (appid != NULL && __check_restart(appid)) {
			_release_srv(appid);
		}
	}

	__send_app_termination_signal(pid);
}

static gboolean __sigchld_handler(gpointer data)
{
	int fd = (int)data;
	struct signalfd_siginfo si;

	while (1) {
		int nr = read(fd, &si, sizeof(struct signalfd_siginfo));

		if (nr != sizeof(struct signalfd_siginfo))
			break;
		while (1) {
			int status;
			pid_t pid = waitpid(-1, &status, WNOHANG);

			if (pid <= 0)
				break;
			_D("Sig child %d", pid);
			__release_app(pid);
		}

	}

	return TRUE;
}

int _signal_block_sigchld(void)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &oldmask) == -1) {
		_E("failed to sigprocmask");
		return -1;
	}

	return __signal_get_sigchld_fd(mask);
}

int _signal_unblock_sigchld(void)
{
	if(sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) {
		_E("SIG_SETMASK error");
		return -1;
	}

	_D("SIGCHLD unblocked");
	return 0;
}

int _request_init(struct amdmgr *amd, int fd_sig)
{
	int fd;
	int r;
	GPollFD *gpollfd;
	GPollFD *gpollfd_sig;
	GSource *src;
	GSource *src_sig;
	DBusError error;

	fd = __create_server_sock(AUL_UTIL_PID);
	if (fd < 0) {
		_E("fail to create server sock");
		return -1;
	}
	src = g_source_new(&funcs, sizeof(GSource));

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	if (gpollfd == NULL) {
		g_source_unref(src);
		close(fd);
		return -1;
	}

	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __request_handler,
			(gpointer) gpollfd, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);

	r = g_source_attach(src, NULL);
	if (r  == 0) {
		_E("fail to attach the source : %d", r);
		return -1;
	}

	src_sig = g_source_new(&funcs, sizeof(GSource));

	gpollfd_sig = (GPollFD *) g_malloc(sizeof(GPollFD));
	if (gpollfd_sig == NULL) {
		g_source_unref(src_sig);
		close(fd_sig);
		return -1;
	}

	gpollfd_sig->events = G_IO_IN;
	gpollfd_sig->fd = fd_sig;

	g_source_add_poll(src_sig, gpollfd_sig);
	g_source_set_callback(src_sig, (GSourceFunc) __sigchld_handler,
			(gpointer) fd_sig, NULL);
	g_source_set_priority(src_sig, G_PRIORITY_DEFAULT);
	r = g_source_attach(src_sig, NULL);
	if (r  == 0) {
		_E("fail to attach the source : %d", r);
		return -1;
	}

	_raf = amd->af;

	r = rua_init();
	r = rua_clear_history();

	_D("rua_clear_history : %d", r);

	dbus_error_init(&error);
	bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);

#ifdef _APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL
	home_appid = vconf_get_str(VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME);
	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME, __home_appid_vconf_cb, NULL) != 0) {
		_E("Unable to register callback for VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME\n");
	}
#endif

	restart_tbl = g_hash_table_new(g_str_hash, g_str_equal);
	return 0;
}

#ifdef _APPFW_FEATURE_SEND_HOME_LAUNCH_SIGNAL
const char* _get_home_appid(void)
{
	return home_appid;
}
#endif

