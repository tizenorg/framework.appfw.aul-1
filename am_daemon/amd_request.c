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
#include <rua.h>
#include <proc_stat.h>
#include <security-server.h>
#include <vconf.h>

#include "amd_config.h"
#include "simple_util.h"
#include "app_sock.h"
#include "app_signal.h"
#include "aul_util.h"
#include "amd_request.h"
#include "amd_key.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_cgutil.h"
#include "amd_status.h"

#include <pkgmgr-info.h>

#define INHOUSE_UID     5000

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
#define METADATA_MULTI_INSTANCE		"http://developer.samsung.com/tizen/metadata/multiinstance"
#endif

struct appinfomgr *_raf;
struct cginfo *_rcg;
static DBusConnection *bus = NULL;
char *home_appid = NULL;


static int __send_result_to_client(int fd, int res);
static gboolean __request_handler(gpointer data);

static int __send_result_to_client(int fd, int res)
{
	_D("__send_result_to_client, res: %d", fd, res);

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

	_D("__forward_cmd: %d %d", cr_pid, pgid);

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
	if (cmd == APP_RESUME_BY_PID)
		proc_group_change_status(PROC_CGROUP_SET_RESUME_REQUEST, pid, NULL);
	else
		proc_group_change_status(PROC_CGROUP_SET_TERMINATE_REQUEST, pid, NULL);

	_D("__app_process_by_pid, cmd: %d, pid: %d, ", cmd, pid);
	switch (cmd) {
	case APP_RESUME_BY_PID:
		ret = _resume_app(pid, clifd);
		break;
	case APP_TERM_BY_PID:
	case APP_TERM_BY_PID_WITHOUT_RESTART:
		ret = _term_app(pid, clifd);
		break;
	case APP_KILL_BY_PID:
		if ((ret = _send_to_sigkill(pid)) < 0)
			_E("fail to killing - %d\n", pid);
		__real_send(clifd, ret);
		break;
	case APP_TERM_REQ_BY_PID:
		if ((ret = __app_send_raw(pid, cmd, (unsigned char *)&dummy, sizeof(int))) < 0) {
			_D("terminate req packet send error");
		}
		__real_send(clifd, ret);
		break;
	case APP_TERM_BY_PID_ASYNC:
		if ((ret = __app_send_raw_with_noreply(pid, cmd, (unsigned char *)&dummy, sizeof(int))) < 0) {
			_D("terminate req packet send error");
		}
		__real_send(clifd, ret);
		break;
	}

	return ret;
}

static gboolean __add_history_handler(gpointer user_data)
{
	struct rua_rec rec;
	int ret;
	bundle *kb = NULL;
	char *appid = NULL;
	char *app_path = NULL;
	struct appinfo *ai;
	app_pkt_t *pkt = (app_pkt_t *)user_data;

	if (!pkt)
		return FALSE;

	kb = bundle_decode(pkt->data, pkt->len);
	appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);

#ifdef _APPFW_FEATURE_CONTACT_PHONE_AS_ONE_APP
	// When the Phone is executed, the Contacts is shown on task manager.
	int need_free = 0;
	if (strncmp(appid, "org.tizen.phone", strlen("org.tizen.phone")) == 0)
	{
		appid = strndup("org.tizen.contacts", strlen("org.tizen.contacts"));
		need_free = 1;
	}
#endif
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

	if (kb != NULL)
		bundle_free(kb);
	free(pkt);

#ifdef _APPFW_FEATURE_CONTACT_PHONE_AS_ONE_APP
	if (need_free)
		free(appid);
#endif

	return FALSE;
}

static int __get_pid_cb(void *user_data, const char *group, pid_t pid)
{
	int *sz = user_data;

	_D("%s: %d : %d", *sz, pid);
	*sz = 1; /* 1 is enough */

	return -1; /* stop the iteration */
}

static int __releasable(const char *filename)
{
	int sz;
	int r;

	if (!filename || !*filename) {
		_E("release service: name is empty");
		return -1;
	}

	r = cgutil_exist_group(_rcg, CTRL_MGR, filename);
	if (r == -1) {
		SECURE_LOGE("release service: exist: %s", strerror(errno));
		return -1;
	}
	if (r == 0) {
		SECURE_LOGE("release service: '%s' already not exist", filename);
		return -1;
	}

	sz = 0;
	r = cgutil_group_foreach_pid(_rcg, CTRL_MGR, filename,
			__get_pid_cb, &sz);
	if (r == -1) {
		SECURE_LOGE("release service: '%s' read pid error", filename);
		return -1;
	}
	if (sz > 0) {
		SECURE_LOGE("release service: '%s' group has process", filename);
		return -1;
	}

	return 0;
}

int __release_srv(const char *filename)
{
	int r;
	const struct appinfo *ai;

	r = __releasable(filename);
	if (r == -1)
		return -1;

	ai = (struct appinfo *)appinfo_find(_raf, filename);
	if (!ai) {
		SECURE_LOGE("release service: '%s' not found", filename);
		return -1;
	}

	r = appinfo_get_boolean(ai, AIT_RESTART);
	if (r == 1) {
		SECURE_LOGD("Auto restart set: '%s'", filename);
		return _start_srv(ai, NULL);
	}

	service_release(filename);

	r = cgutil_remove_group(_rcg, CTRL_MGR, filename);
	if (r == -1) {
		SECURE_LOGE("'%s' group remove error: %s", filename, strerror(errno));
		return -1;
	}

	return 0;
}

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

	_D("send dead signal done\n");

	return 0;
}

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

	_D("send dead signal done\n");

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
				appinfo_set_value(ai, AIT_TOGGLE_ORDER, "1");
				break;

			case 1:
				target = appid;
				appinfo_set_value(ai, AIT_TOGGLE_ORDER, "0");
				break;

			default:
				break;
		}
	} else {
		// Main app is running
		if (_status_app_is_running(appid) != -1) {
			_D("Send a request to the running main appid: %s", appid);
			target = appid;
			// Sub app is running
		} else if (_status_app_is_running(multi_appid) != -1) {
			_D("Send a request to the running sub appid: %s", multi_appid);
			target = multi_appid;
		} else {
			_D("Both apps are not running, launch a main app - %s", appid);
			target = appid;
		}
	}

	return target;
}
#endif

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
	char *appid;
	char *term_pid = NULL;
	int pid;
	bundle *kb = NULL;
	const struct appinfo *ai;
	const char *pkg_status;
	item_pkt_t *item;

	if ((pkt = __app_recv_raw(fd, &clifd, &cr)) == NULL) {
		_E("recv error");
		return FALSE;
	}

	_D("__request_handler: %d", pkt->cmd);
	switch (pkt->cmd) {
		case APP_OPEN:
		case APP_RESUME:
		case APP_START:
		case APP_START_RES:
		case APP_START_ASYNC:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::launch", "x");
			if(ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("launch request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				kb = bundle_decode(pkt->data, pkt->len);
				appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
				// Check the multi-instance app
				ai = appinfo_find(_raf, appid);
				if (ai == NULL) {
					_E("no appinfo");
					__real_send(clifd, -1);
					ret = -1;
				} else {
					const char* multi = appinfo_get_value(ai, AIT_MULTI_INSTANCE);
					if( multi && strncmp(multi, "true", strlen("true")) == 0 ) {

						char* multi_appid =__get_metadata_value(appid, METADATA_MULTI_INSTANCE);
						if (multi_appid != NULL)
						{
							_D("Multi-instance main: %s, sub: %s", appid, multi_appid);

							const char* target_appid = __check_target_appid(ai, appid, multi_appid);

							_D("launch a target appid: - %s", target_appid);
							ret = _start_app(target_appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
						} else {
							_D("No multi-instance app information, launch a main appid: - %s", appid);
							ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
						}

						free(multi_appid);
					}
					else
					{
						_D("launch a single-instance appid: %s", appid);
						ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
					}
				}
#else
				ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
#endif

				if(ret > 0 && bundle_get_type(kb, AUL_K_PRELAUCHING) == BUNDLE_TYPE_NONE) {
					item = calloc(1, sizeof(item_pkt_t));
					item->pid = ret;
					strncpy(item->appid, appid, 511);
					free_pkt = 0;

					if (home_appid && strncmp(appid, home_appid, strlen(appid)) == 0)
						__send_home_launch_signal(ret);
#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
					__add_item_running_list(item);
#endif
					g_timeout_add(1000, __add_history_handler, pkt);
				}

				if (kb != NULL)
					bundle_free(kb), kb = NULL;
			}
			break;
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
		case APP_START_MULTI_INSTANCE:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::launch", "x");
			if(ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("launch request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				kb = bundle_decode(pkt->data, pkt->len);
				appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);

				_D("launch a multi-instance appid: %s", appid);
				ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
			}

			if(ret > 0) {
				item = calloc(1, sizeof(item_pkt_t));
				item->pid = ret;
				strncpy(item->appid, appid, 511);
				free_pkt = 0;

				if (home_appid && strncmp(appid, home_appid, strlen(appid)) == 0)
					__send_home_launch_signal(ret);
#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
				__add_item_running_list(item);
#endif
				g_timeout_add(1000, __add_history_handler, pkt);
			}

			if (kb != NULL)
				bundle_free(kb), kb = NULL;

			break;
#endif
		case APP_RESULT:
		case APP_CANCEL:
			kb = bundle_decode(pkt->data, pkt->len);
			ret = __foward_cmd(pkt->cmd, kb, cr.pid);
			//__real_send(clifd, ret);
			close(clifd);
			break;
		case APP_RESUME_BY_PID:
		case APP_TERM_REQ_BY_PID:
			kb = bundle_decode(pkt->data, pkt->len);
			appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
			ret = __app_process_by_pid(pkt->cmd, appid, &cr, clifd);
			break;
		case APP_TERM_BY_PID_WITHOUT_RESTART:
		case APP_TERM_BY_PID_ASYNC:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::terminate", "x");
			if(ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("terminate request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				kb = bundle_decode(pkt->data, pkt->len);
				term_pid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
				appid = _status_app_get_appid_bypid(atoi(term_pid));
				ai = appinfo_find(_raf, appid);
				if(ai) {
					appinfo_set_value(ai, AIT_STATUS, "norestart");
					ret = __app_process_by_pid(pkt->cmd, term_pid, &cr, clifd);
				} else {
					ret = -1;
				}
			}
			break;
		case APP_TERM_BY_PID:
		case APP_KILL_BY_PID:
			ret = security_server_check_privilege_by_sockfd(clifd, "aul::terminate", "x");
			if(ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
				_E("terminate request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
			} else {
				kb = bundle_decode(pkt->data, pkt->len);
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
			strncpy(appid, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
			ret = _status_app_is_running_v2(appid);
			SECURE_LOGD("APP_IS_RUNNING : %s : %d",appid, ret);
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
			if(*status == STATUS_NORESTART) {
				appid = _status_app_get_appid_bypid(cr.pid);
				ai = appinfo_find(_raf, appid);
				appinfo_set_value(ai, AIT_STATUS, "norestart");
			} else {
				ret = _status_update_app_info_list(cr.pid, *status);
			}
			//__send_result_to_client(clifd, ret);
			close(clifd);
			break;
		case APP_RELEASED:
			appid = malloc(MAX_PACKAGE_STR_SIZE);
			strncpy(appid, (const char*)&pkt->data[1], MAX_PACKAGE_STR_SIZE-1);
			ai = appinfo_find(_raf, appid);
			pkg_status = appinfo_get_value(ai, AIT_STATUS);
			SECURE_LOGD("appid(%s) pkg_status(%s)", appid, pkg_status);
			if(pkg_status && strncmp(pkg_status, "blocking", 8) == 0) {
				appinfo_set_value(ai, AIT_STATUS, "restart");
			} else if (pkg_status && strncmp(pkg_status, "norestart", 9) == 0) {
				appinfo_set_value(ai, AIT_STATUS, "installed");
			} else {
				ret = __release_srv(appid);
			}
			__send_result_to_client(clifd, ret);
			ret = _status_app_is_running(appid);
			SECURE_LOGI("appid(%s) dead pid(%d)", appid, ret);
			if(ret > 0)
				__send_app_termination_signal(ret);
			free(appid);
			break;
		case APP_RUNNING_LIST_UPDATE:
			/*kb = bundle_decode(pkt->data, pkt->len);
			  appid = (char *)bundle_get_val(kb, AUL_K_APPID);
			  app_path = (char *)bundle_get_val(kb, AUL_K_EXEC);
			  tmp_pid = (char *)bundle_get_val(kb, AUL_K_PID);
			  pid = atoi(tmp_pid);
			  ret = _status_add_app_info_list(appid, app_path, pid);*/
			ret = 0;
			__send_result_to_client(clifd, ret);
			break;
		default:
			_E("no support packet");
			close(clifd);
	}

	if (free_pkt)
		free(pkt);

	if (kb != NULL)
		bundle_free(kb), kb = NULL;

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

int _request_init(struct amdmgr *amd)
{
	int fd;
	int r;
	GPollFD *gpollfd;
	GSource *src;
	DBusError error;

	fd = __create_server_sock(AUL_UTIL_PID);
	src = g_source_new(&funcs, sizeof(GSource));

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __request_handler,
			(gpointer) gpollfd, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);

	r = g_source_attach(src, NULL);
	if (r  == 0)
	{
		_E("fail to attach the source : %d", r);
		return -1;
	}

	_raf = amd->af;
	_rcg = amd->cg;

	r = rua_init();
	r = rua_clear_history();

	_D("rua_clear_history : %d", r);

	dbus_error_init(&error);
	bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
	home_appid = vconf_get_str(VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME);
	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME, __home_appid_vconf_cb, NULL) != 0) {
		_E("Unable to register callback for VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME\n");
	}

	return 0;
}


