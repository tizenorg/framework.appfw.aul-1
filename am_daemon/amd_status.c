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
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include <aul.h>
#include <string.h>
#include <Ecore.h>
#include <proc_stat.h>
#include <pkgmgr-info.h>
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
#include <vconf/vconf.h>
#endif
#include <bundle_internal.h>

#include "launch.h"
#include "amd_config.h"
#include "amd_status.h"
#include "amd_appinfo.h"
#include "amd_launch.h"
#include "aul_util.h"
#include "simple_util.h"
#include "app_sock.h"
#include "menu_db_util.h"
#include "amd_app_group.h"

#define WINDOW_READY	"/tmp/.wm_ready"

#ifdef _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT
int cooldown_status = 0;
#endif // _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT

GSList *app_status_info_list = NULL;
GHashTable *pkg_status_info_table = NULL;
GHashTable *app_running_cache = NULL;
struct appinfomgr *_saf = NULL;

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
#define AMD_LOG_BUFFER_SIZE 10000
#define AMD_LOG_BUFFER_STRING_SIZE 128
#define AMD_LOG_FILE "/var/log/amd.log"

static int log_index = 0;
static int log_fd = 0;
#endif

static int __send_result_to_client(int clifd, int res)
{
	if (clifd < 0)
		return -1;

	if (send(clifd, &res, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	close(clifd);

	return 0;
}

static app_status_info_t* __get_app_status_info(int pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if (info_t && info_t->pid == pid) {
			return info_t;
		}
	}

	return NULL;
}

static void __add_running_cache(const char *appid, int pid)
{
	if (!appid || pid < 1)
		return;

	if (!app_running_cache)
		app_running_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	GSList *pid_list = NULL;

	pid_list = (GSList *)g_hash_table_lookup(app_running_cache, appid);
	if (pid_list == NULL) {
		pid_list = g_slist_append(pid_list, GINT_TO_POINTER(pid));
		g_hash_table_insert(app_running_cache, g_strdup(appid), pid_list);
	} else {
		if (!g_slist_find(pid_list, GINT_TO_POINTER(pid)))
			pid_list = g_slist_append(pid_list, GINT_TO_POINTER(pid));
	}
}

static void __remove_running_cache(const char *appid, int pid)
{
	if (!appid || pid < 1)
		return;

	if (!app_running_cache)
		return;

	GSList *pid_list = NULL;
	GSList *remain_list = NULL;

	pid_list = (GSList *)g_hash_table_lookup(app_running_cache, appid);
	if (pid_list == NULL)
		return;

	remain_list = g_slist_remove(pid_list, GINT_TO_POINTER(pid));
	if (remain_list && remain_list != pid_list) {
		g_hash_table_replace(app_running_cache, g_strdup(appid), remain_list);
	}

	if (!remain_list) {
		g_hash_table_remove(app_running_cache, appid);
	}
}

static void __add_pkg_info(const char *pkgid, app_status_info_t *appinfo)
{
	pkg_status_info_t *pkginfo = NULL;

	if (pkgid == NULL || appinfo == NULL) {
		_E("empty arguments: %s", pkgid == NULL ? (appinfo == NULL ? "appinfo, pkgid" : "pkgid") : "appinfo");
		return;
	}

	if (pkg_status_info_table == NULL)
		pkg_status_info_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

	pkginfo = g_hash_table_lookup(pkg_status_info_table, pkgid);
	if (pkginfo == NULL) {
		pkginfo = (pkg_status_info_t *)malloc(sizeof(pkg_status_info_t));
		if (pkginfo == NULL) {
			_E("failed to allocate memory");
			return;
		}
		memset(pkginfo, 0, sizeof(pkg_status_info_t));
		pkginfo->pkgid = strdup(pkgid);
		if (pkginfo->pkgid == NULL) {
			free(pkginfo);
			_E("failed to allocate memory");
			return;
		}
		g_hash_table_insert(pkg_status_info_table, pkginfo->pkgid, pkginfo);
	}

	pkginfo->status = appinfo->status;
	appinfo->pkginfo = pkginfo;

	if (appinfo->status == STATUS_SERVICE) {
		pkginfo->svc_list = g_slist_append(pkginfo->svc_list, appinfo);
	}
	else {
		pkginfo->ui_list = g_slist_append(pkginfo->ui_list, appinfo);
	}
}

static int __get_ui_app_status_pkg_info(pkg_status_info_t *pkginfo)
{
	app_status_info_t *appinfo = NULL;
	GSList *iter = NULL;
	int status = STATUS_BG;

	if (pkginfo == NULL)
		return -1;

	iter = pkginfo->ui_list;
	while (iter) {
		appinfo = (app_status_info_t *)iter->data;
		if (appinfo->status != STATUS_BG) {
			status = appinfo->status;
		}

		iter = g_slist_next(iter);
	}

	return status;
}

static int __update_pkg_info(const char *pkgid, app_status_info_t *appinfo)
{
	pkg_status_info_t *pkginfo = NULL;
	int ret = 0;

	if (pkgid == NULL || appinfo == NULL)
		return -1;

	if (pkg_status_info_table == NULL) {
		return -1;
	}

	pkginfo = (pkg_status_info_t *)g_hash_table_lookup(pkg_status_info_table, pkgid);
	if (pkginfo == NULL) {
		_E("pkgid(%s) is not on list");
		return -1;
	}

	if (pkginfo->ui_list) {
		ret = __get_ui_app_status_pkg_info(pkginfo);
		if (ret > -1)
			pkginfo->status = ret;
	}
	else
		pkginfo->status = STATUS_SERVICE;

	return 0;
}


static void __remove_pkg_info(const char *pkgid, app_status_info_t *appinfo)
{
	pkg_status_info_t *pkginfo = NULL;
	const struct appinfo *ai = NULL;
	const char *component_type = NULL;

	if (pkgid == NULL || appinfo == NULL) {
		_E("empty arguments: %s", pkgid == NULL ? (appinfo == NULL ? "appinfo, pkgid" : "pkgid") : "appinfo");
		return;
	}

	ai = appinfo_find(_saf, appinfo->appid);
	component_type = appinfo_get_value(ai, AIT_COMPTYPE);

	pkginfo = (pkg_status_info_t *)g_hash_table_lookup(pkg_status_info_table, pkgid);
	if (pkginfo == NULL) {
		_E("pkgid(%s) is not on list");
		return;
	}

	if (component_type && strcmp(component_type, APP_TYPE_SERVICE) == 0) {
		if (pkginfo->svc_list) {
			pkginfo->svc_list = g_slist_remove(pkginfo->svc_list, appinfo);
			_D("STATUS_SERVICE : appid(%s)", appinfo->appid);
		}
	} else {
		if (pkginfo->ui_list) {
			pkginfo->ui_list = g_slist_remove(pkginfo->ui_list, appinfo);
			_D("~STATUS_SERVICE : appid(%s)", appinfo->appid);
		}
	}

	if (!pkginfo->svc_list && !pkginfo->ui_list) {
		g_hash_table_remove(pkg_status_info_table, pkgid);
		if (pkginfo->pkgid) {
			free(pkginfo->pkgid);
			pkginfo->pkgid = NULL;
		}
		free(pkginfo);
	}
}

static void __remove_all_shared_info(app_status_info_t *info_t)
{
	if (info_t && info_t->shared_info_list) {
		GList *list = info_t->shared_info_list;

		while (list) {
			shared_info_t *sit = (shared_info_t*)list->data;

			if (sit) {
				if (sit->owner_exec_label)
					free(sit->owner_exec_label);
				if (sit->paths) {
					int i = 0;
					while (1) {
						if (sit->paths[i] == NULL) {
							free(sit->paths);
							break;
						}

						free(sit->paths[i]);
						i++;
					}
				}
				free(sit);
			}
			list = g_list_next(list);
		}

		g_list_free(info_t->shared_info_list);
		info_t->shared_info_list = NULL;
	}
}

static void __destroy_app_status_info(app_status_info_t *info_t)
{
	if (info_t == NULL)
		return;

	if (info_t->appid) {
		free(info_t->appid);
		info_t->appid = NULL;
	}

	if (info_t->app_path) {
		free(info_t->app_path);
		info_t->app_path = NULL;
	}

	if (info_t->caller) {
		free(info_t->caller);
		info_t->caller = NULL;
	}

	if (info_t->pkgid) {
		free(info_t->pkgid);
		info_t->pkgid = NULL;
	}

	if (info_t->exec_label) {
		free(info_t->exec_label);
		info_t->exec_label = NULL;
	}

	__remove_all_shared_info(info_t);
	free(info_t);
}

int _status_add_app_info_list(const char *appid, const char *app_path,
	const char *caller, int pid, int pad_pid, int is_subapp)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;
	const struct appinfo *ai;
	const char *component_type = NULL;
	const char *pkgid = NULL;

	if (!appid || !app_path)
		return -1;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if (pid == info_t->pid) {
			if (!strcmp(appid, info_t->appid)) {
				return 0;
			} else {
				__remove_running_cache(info_t->appid, info_t->pid);
				app_status_info_list = g_slist_remove(app_status_info_list, info_t);

				__remove_pkg_info(info_t->pkgid, info_t);

				__destroy_app_status_info(info_t);
				break;
			}
		}
	}

	ai = appinfo_find(_saf, appid);

	info_t = malloc(sizeof(app_status_info_t));
	if (info_t == NULL) {
		_E("out of memory");
		return -1;
	}

	memset(info_t, 0, sizeof(app_status_info_t));

	info_t->appid = strdup(appid);
	if (info_t->appid == NULL)
		goto error;

	info_t->app_path = strdup(app_path);
	if (info_t->app_path == NULL)
		goto error;

	if (caller) {
		info_t->caller = strdup(caller);
		if (info_t->caller == NULL)
			goto error;
	}

	component_type = appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type && strcmp(component_type, APP_TYPE_SERVICE) == 0) {
		info_t->status = STATUS_SERVICE;
	} else {
		info_t->status = STATUS_LAUNCHING;
	}

	pkgid = appinfo_get_value(ai, AIT_PKGID);
	if (pkgid == NULL)
		goto error;

	info_t->pid = pid;
	info_t->pad_pid = pad_pid;
	info_t->is_subapp = is_subapp;
	info_t->shared_info_list = NULL;
	info_t->exec_label = NULL;

	info_t->pkgid = strdup(pkgid);
	if (info_t->pkgid == NULL)
		goto error;

	app_status_info_list = g_slist_append(app_status_info_list, info_t);

	__add_pkg_info(pkgid, info_t);

	__add_running_cache(info_t->appid, pid);

	_D("pid(%d) appid(%s) pkgid(%s) comp(%s)", pid, appid, pkgid, component_type);

	return 0;

error:
	__destroy_app_status_info(info_t);

	return -1;
}

static Eina_Bool __app_terminate_timer_cb(void *data)
{
	int pid = (int)data;
	int ret = 0;

	_D("pid(%d)", pid);

	ret = kill(pid, SIGKILL);
	if (ret == -1)
		_W("send SIGKILL: %s", strerror(errno));

	return ECORE_CALLBACK_CANCEL;
}

int _status_update_app_info_list(int pid, int status, gboolean force)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	_D("pid(%d) status(%d)", pid, status);
	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid) {
			info_t->status = status;
			if(status == STATUS_DYING) {
				if(info_t->pad_pid != DEBUG_LAUNCHPAD_PID)
					ecore_timer_add(5, __app_terminate_timer_cb, (void *)info_t->pid);
			}
			__update_pkg_info(info_t->pkgid, info_t);

			_D("pid(%d) appid(%s) pkgid(%s) status(%d)", pid, info_t->appid, info_t->pkgid, info_t->status);
			break;
		}
	}

	app_group_set_status(pid, status, force);

	return 0;
}

int _status_remove_app_info_list(int pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid) {
			__remove_running_cache(info_t->appid, info_t->pid);
			app_status_info_list = g_slist_remove(app_status_info_list, info_t);

			__remove_pkg_info(info_t->pkgid, info_t);

			__destroy_app_status_info(info_t);
			break;
		}
	}

	return 0;
}

int _status_get_app_info_status(int pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid) {
			return info_t->status;
		}
	}

	return app_group_get_status(pid);
}

static gint __find_app_bypid(gconstpointer app_data, gconstpointer pid_data)
{
	int pid = GPOINTER_TO_INT(pid_data);
	app_status_info_t *appinfo = (app_status_info_t *)app_data;

	if (appinfo && pid && appinfo->pid == pid)
		return 0;

	return -1;
}

void _status_find_service_apps(int pid, enum app_status status, void (*send_event_to_svc_core) (int))
{
	GSList *app_list = NULL;
	GSList *svc_list = NULL;
	app_status_info_t *info_t = NULL;
	app_status_info_t *svc_info_t = NULL;

	app_list = g_slist_find_custom(app_status_info_list, GINT_TO_POINTER(pid), __find_app_bypid);

	if (!app_list) {
		_E("unable to find app by pid:%d", pid);
		return;
	}

	info_t = (app_status_info_t *)app_list->data;
	if (info_t && info_t->pkginfo && info_t->pkginfo->status == status)
		svc_list = info_t->pkginfo->svc_list;

	while (svc_list) {
		svc_info_t = (app_status_info_t *)svc_list->data;
		if (svc_info_t)
			send_event_to_svc_core(svc_info_t->pid);

		svc_list = g_slist_next(svc_list);
	}
}

void _status_check_service_only(int pid, void (*send_event_to_svc_core) (int))
{
	GSList *app_list = NULL;
	GSList *ui_list = NULL;
	app_status_info_t *info_t = NULL;
	app_status_info_t *ui_info_t = NULL;
	int ui_cnt = 0;

	app_list = g_slist_find_custom(app_status_info_list, GINT_TO_POINTER(pid), __find_app_bypid);

	if (!app_list) {
		_E("unable to find app by pid:%d", pid);
		return;
	}

	info_t = (app_status_info_t *)app_list->data;
	ui_list = info_t->pkginfo->ui_list;
	while (ui_list) {
		ui_info_t = (app_status_info_t *)ui_list->data;
		if (ui_info_t && _status_app_is_running_v2(ui_info_t->appid) > 0) {
			ui_cnt++;
		}
		ui_list = g_slist_next(ui_list);
	}

	if (ui_cnt == 0)
		send_event_to_svc_core(pid);
}

int _status_update_app_info_caller_pid(int pid, int caller_pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if (info_t && info_t->pid == pid) {
			info_t->last_caller_pid = caller_pid;
			return 0;
		}
	}
	return -1;
}

int _status_set_exec_label(int pid, const char *exec_label)
{
	app_status_info_t *info_t = __get_app_status_info(pid);

	if (info_t) {
		if (info_t->exec_label)
			free(info_t->exec_label);
		info_t->exec_label = strdup(exec_label);
		return 0;
	}

	return -1;
}

const char* _status_get_exec_label(int pid)
{
	app_status_info_t *info_t = __get_app_status_info(pid);

	if (info_t)
		return info_t->exec_label;

	return NULL;
}

int _status_add_shared_info(int pid, const char *exec_label, char **paths)
{
	shared_info_t *sit = (shared_info_t*)malloc(sizeof(shared_info_t));

	if (!sit)
		return -1;

	sit->owner_exec_label = strdup(exec_label);
	sit->paths = paths;

	app_status_info_t* info_t = __get_app_status_info(pid);

	if (info_t) {
		info_t->shared_info_list = g_list_append(info_t->shared_info_list, sit);
		return 0;
	}

	if (sit->owner_exec_label)
		free(sit->owner_exec_label);
	free(sit);
	return -1;
}

int _status_clear_shared_info_list(int pid)
{
	app_status_info_t* info_t = __get_app_status_info(pid);

	if (info_t) {
		__remove_all_shared_info(info_t);
		return 0;
	}

	return -1;
}

GList* _status_get_shared_info_list(int pid)
{
	app_status_info_t *info_t = __get_app_status_info(pid);

	if (info_t)
		return info_t->shared_info_list;

	return NULL;
}

int _status_get_app_info_last_caller_pid(int pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if (info_t && info_t->pid == pid) {
			return info_t->last_caller_pid;
		}
	}
	return -1;
}

int _status_app_is_running(const char *appid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if( strncmp(appid, info_t->appid, MAX_PACKAGE_STR_SIZE) == 0 && !info_t->is_subapp) {
			return info_t->pid;
		}
	}
	return -1;
}

char* _status_app_get_appid_bypid(int pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if( pid == info_t->pid ) {
			return info_t->appid;
		}
	}
	return NULL;
}

char* _status_get_caller_by_appid(const char *appid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if( strncmp(appid, info_t->appid, MAX_PACKAGE_STR_SIZE-1) == 0 && !info_t->is_subapp) {
			return info_t->caller;
		}
	}

	return NULL;
}


int _status_send_running_appinfo(int fd)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;
	app_pkt_t *pkt = NULL;
	char tmp_pid[MAX_PID_STR_BUFSZ];

	pkt = (app_pkt_t *)malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (!pkt) {
		_E("malloc fail");
		__send_result_to_client(fd, -1);
		return -1;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if (app_group_is_sub_app(info_t->pid))
			continue;

		snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", info_t->pid);
		strncat((char *)pkt->data, tmp_pid, MAX_PID_STR_BUFSZ);
		strncat((char *)pkt->data, ":", 1);
		strncat((char *)pkt->data, info_t->appid, MAX_PACKAGE_STR_SIZE);
		strncat((char *)pkt->data, ":", 1);
		strncat((char *)pkt->data, info_t->app_path, MAX_PACKAGE_APP_PATH_SIZE);
		strncat((char *)pkt->data, ";", 1);
	}

	pkt->cmd = APP_RUNNING_INFO_RESULT;
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if (pkt)
		free(pkt);

	close(fd);

	return 0;
}

int _status_app_is_running_v2(const char *appid)
{
	char *apppath = NULL;
	int ret = 0;
	int i = 0;
	const char *ae = NULL;
	const struct appinfo *ai;

	if(appid == NULL)
		return -1;

	ai = appinfo_find(_saf, appid);

	if (ai == NULL)
		return -1;

	ae = appinfo_get_value(ai, AIT_EXEC);
	if (ae == NULL)
		return -1;

	apppath = strdup(ae);
	if (apppath == NULL)
		return -1;

	/*truncate apppath if it includes default bundles */
	while (apppath[i] != 0) {
		if (apppath[i] == ' ' || apppath[i] == '\t') {
			apppath[i]='\0';
			break;
		}
		i++;
	}

	ret = __proc_iter_cmdline(NULL, apppath);

	free(apppath);

	return ret;
}

int _status_app_is_running_from_cache(const char *appid)
{
	const char *path = NULL;
	GSList *pid_list = NULL;
	const struct appinfo *ai;

	if (app_running_cache)
		pid_list = (GSList *)g_hash_table_lookup(app_running_cache, appid);

	if (pid_list) {
		ai = appinfo_find(_saf, appid);
		if (ai == NULL)
			return -1;

		path = appinfo_get_value(ai, AIT_EXEC);
		if (path == NULL)
			return -1;

		while (pid_list) {
			if (__proc_check_app(path, GPOINTER_TO_INT(pid_list->data))) {
				_D("is_running hit cache, return immediately");
				return GPOINTER_TO_INT(pid_list->data);
			} else {
				_E("is_running garbage, pid: %d", GPOINTER_TO_INT(pid_list->data));
				__remove_running_cache(appid, GPOINTER_TO_INT(pid_list->data));
			}
			pid_list = pid_list->next;
		}
	}

	return 0;
}

int _status_app_is_running_v2_cached(const char *appid)
{
	int ret = 0;

	ret = _status_app_is_running_from_cache(appid);
	if (ret > 0)
		return ret;

	ret = _status_app_is_running_v2(appid);
	if (ret > 0) {
		_E("is running missing app detected: %s (%d)", appid, ret);
		__add_running_cache((char *)appid, ret);
	}

	return ret;
}

static int __get_pkginfo(const char *dname, const char *cmdline, void *priv)
{
	app_info_from_db *menu_info;
	char *r_info;
	char *pkgname = NULL;
	char *app_path = NULL;

	r_info = (char *)priv;

	if ((menu_info = _get_app_info_from_db_by_apppath(cmdline)) == NULL)
		goto out;
	else {
		pkgname = _get_pkgname(menu_info);
		if (pkgname == NULL)
			goto out;

		app_path = _get_app_path(menu_info);
		if (app_path == NULL)
			goto out;

		strncat(r_info, dname, 8);
		strncat(r_info, ":", 1);
		strncat(r_info, pkgname, MAX_PACKAGE_STR_SIZE);
		strncat(r_info, ":", 1);
		strncat(r_info, app_path, MAX_PACKAGE_APP_PATH_SIZE);
		strncat(r_info, ";", 1);
	}

 out:
	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);
	return 0;
}

int _status_send_running_appinfo_v2(int fd)
{
	app_pkt_t *pkt = NULL;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (!pkt) {
		_E("malloc fail");
		__send_result_to_client(fd, -1);
		return -1;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	__proc_iter_cmdline(__get_pkginfo, pkt->data);

	pkt->cmd = APP_RUNNING_INFO_RESULT;
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if (pkt)
		free(pkt);

	close(fd);

	return 0;
}

int _status_get_pkgname_bypid(int pid, char *pkgname, int len)
{
	char *cmdline;
	app_info_from_db *menu_info;

	cmdline = __proc_get_cmdline_bypid(pid);
	if (cmdline == NULL)
		return -1;

	if ((menu_info = _get_app_info_from_db_by_apppath(cmdline)) == NULL) {
		free(cmdline);
		return -1;
	} else {
		snprintf(pkgname, len, "%s", _get_pkgname(menu_info));
	}

	free(cmdline);
	_free_app_info_from_db(menu_info);

	return 0;
}

int _status_get_appid_bypid(int fd, int pid)
{
	app_pkt_t *pkt = NULL;
	int pgid;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = APP_GET_INFO_ERROR;

	if (_status_get_pkgname_bypid(pid, (char *)pkt->data, MAX_PACKAGE_STR_SIZE) == 0) {
		SECURE_LOGD("appid for %d is %s", pid, pkt->data);
		pkt->cmd = APP_GET_INFO_OK;
		goto out;
	}
	/* support app launched by shell script*/
	_D("second chance");
	pgid = getpgid(pid);
	if (pgid <= 1)
		goto out;

	_D("second change pgid = %d, pid = %d", pgid, pid);
	if (_status_get_pkgname_bypid(pgid, (char *)pkt->data, MAX_PACKAGE_STR_SIZE) == 0)
		pkt->cmd = APP_GET_INFO_OK;

 out:
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if(pkt)
		free(pkt);

	close(fd);

	return 0;
}

static int __get_pkgid_bypid(int pid, char *pkgid, int len)
{
	char *cmdline;
	app_info_from_db *menu_info;

	cmdline = __proc_get_cmdline_bypid(pid);
	if (cmdline == NULL)
		return -1;

	if ((menu_info = _get_app_info_from_db_by_apppath(cmdline)) == NULL) {
		free(cmdline);
		return -1;
	} else
		snprintf(pkgid, len, "%s", _get_pkgid(menu_info));

	free(cmdline);
	_free_app_info_from_db(menu_info);

	return 0;
}

int _status_get_pkgid_bypid(int fd, int pid)
{
	app_pkt_t *pkt = NULL;
	int pgid;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = APP_GET_INFO_ERROR;

	if (__get_pkgid_bypid(pid, (char *)pkt->data, MAX_PACKAGE_STR_SIZE) == 0) {
		SECURE_LOGD("appid for %d is %s", pid, pkt->data);
		pkt->cmd = APP_GET_INFO_OK;
		goto out;
	}
	/* support app launched by shell script*/
	_D("second chance");
	pgid = getpgid(pid);
	if (pgid <= 1)
		goto out;

	_D("second change pgid = %d, pid = %d", pgid, pid);
	if (__get_pkgid_bypid(pgid, (char *)pkt->data, MAX_PACKAGE_STR_SIZE) == 0)
		pkt->cmd = APP_GET_INFO_OK;

 out:
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if(pkt)
		free(pkt);

	close(fd);

	return 0;
}

int _status_get_cmdline(int fd, int pid)
{
	app_pkt_t *pkt = NULL;
	int len;
	char *cmdline;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = APP_GET_INFO_ERROR;

	cmdline = __proc_get_cmdline_bypid(pid);
	if (cmdline == NULL)
		goto out;
	_E("cmdline : %s", cmdline);

	strncpy((char *)pkt->data, cmdline, MAX_PACKAGE_STR_SIZE);
	_E("pkt->data : %s", pkt->data);
	pkt->cmd = APP_GET_INFO_OK;

 out:
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((len = send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	free(cmdline);

	if(pkt)
		free(pkt);

	close(fd);

	return 0;
}


int _status_send_group_info(int fd)
{
	GSList *iter = NULL;
	GSList *iter2 = NULL;
	app_status_info_t *info_t = NULL;
	app_status_info_t *info_t2 = NULL;
	app_pkt_t *pkt = NULL;
	char buf[2048];

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (!pkt) {
		_E("malloc fail");
		__send_result_to_client(fd, -1);
		return -1;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	snprintf(buf, sizeof(buf), "=======================STATUS_LAUNCHING======================\n");
	strncat((char *)pkt->data, buf, 2048);
	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(info_t->status == STATUS_LAUNCHING) {
			snprintf(buf, sizeof(buf), "%s(%d)=>", info_t->appid, info_t->pid);
			strncat((char *)pkt->data, buf, 2048);
			snprintf(buf, sizeof(buf), "||\n");
			strncat((char *)pkt->data, buf, 2048);
		}
	}

	snprintf(buf, sizeof(buf), "\n");
	strncat((char *)pkt->data, buf, 2048);

	snprintf(buf, sizeof(buf), "=======================STATUS_FG=============================\n");
	strncat((char *)pkt->data, buf, 2048);
	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		_D("%s(%d)=>", info_t->appid, info_t->pid);
		if(info_t->status != STATUS_VISIBLE) {
				continue;
		}

		snprintf(buf, sizeof(buf), "%s(%d)=>", info_t->appid, info_t->pid);
		strncat((char *)pkt->data, buf, 2048);
		snprintf(buf, sizeof(buf), "||\n");
		strncat((char *)pkt->data, buf, 2048);

	}

	snprintf(buf, sizeof(buf), "\n");
	strncat((char *)pkt->data, buf, 2048);

	snprintf(buf, sizeof(buf), "=======================STATUS_BG=============================\n");
	strncat((char *)pkt->data, buf, 2048);

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		if(info_t->status != STATUS_BG)
			continue;
		snprintf(buf, sizeof(buf), "%s(%d)=>", info_t->appid, info_t->pid);
		strncat((char *)pkt->data, buf, 2048);
		snprintf(buf, sizeof(buf), "||\n");
		strncat((char *)pkt->data, buf, 2048);

	}

	snprintf(buf, sizeof(buf), "\n");
	strncat((char *)pkt->data, buf, 2048);

	snprintf(buf, sizeof(buf), "=======================STATUS_SERVICE(FG)====================\n");
	strncat((char *)pkt->data, buf, 2048);
	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(info_t->status == STATUS_SERVICE && info_t->pkginfo->status == STATUS_VISIBLE) {
			snprintf(buf, sizeof(buf), "[pkgid(%s)]", info_t->pkginfo->pkgid);
			strncat((char *)pkt->data, buf, 2048);
			for (iter2 = info_t->pkginfo->svc_list; iter2 != NULL; iter2 = g_slist_next(iter2))
			{
				info_t2 = (app_status_info_t *)iter2->data;
				snprintf(buf, sizeof(buf), "%s(%d)=>", info_t2->appid, info_t2->pid);
				strncat((char *)pkt->data, buf, 2048);
			}
			snprintf(buf, sizeof(buf), "||\n");
			strncat((char *)pkt->data, buf, 2048);
		}
	}
	snprintf(buf, sizeof(buf), "\n");
	strncat((char *)pkt->data, buf, 2048);

	snprintf(buf, sizeof(buf), "=======================STATUS_SERVICE(BG)====================\n");
	strncat((char *)pkt->data, buf, 2048);
	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(info_t->status == STATUS_SERVICE && info_t->pkginfo->status == STATUS_BG) {
			snprintf(buf, sizeof(buf), "[pkgid(%s)]", info_t->pkginfo->pkgid);
			strncat((char *)pkt->data, buf, 2048);
			for (iter2 = info_t->pkginfo->svc_list; iter2 != NULL; iter2 = g_slist_next(iter2))
			{
				info_t2 = (app_status_info_t *)iter2->data;
				snprintf(buf, sizeof(buf), "%s(%d)=>", info_t2->appid, info_t2->pid);
				strncat((char *)pkt->data, buf, 2048);
			}
			snprintf(buf, sizeof(buf), "||\n");
			strncat((char *)pkt->data, buf, 2048);
		}
	}
	snprintf(buf, sizeof(buf), "\n");
	strncat((char *)pkt->data, buf, 2048);

	snprintf(buf, sizeof(buf), "=======================STATUS_SERVICE========================\n");
	strncat((char *)pkt->data, buf, 2048);
	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(info_t->status == STATUS_SERVICE && info_t->pkginfo->status == STATUS_SERVICE) {
			snprintf(buf, sizeof(buf), "[pkgid(%s)]", info_t->pkginfo->pkgid);
			_D("[pkgid(%s)]", info_t->pkginfo->pkgid);
			strncat((char *)pkt->data, buf, 2048);
			for (iter2 = info_t->pkginfo->svc_list; iter2 != NULL; iter2 = g_slist_next(iter2))
			{
				info_t2 = (app_status_info_t *)iter2->data;
				snprintf(buf, sizeof(buf), "%s(%d)=>", info_t2->appid, info_t2->pid);
				strncat((char *)pkt->data, buf, 2048);
			}
			snprintf(buf, sizeof(buf), "||\n");
			strncat((char *)pkt->data, buf, 2048);
		}
	}

	snprintf(buf, sizeof(buf), "************************************************************\n");
	strncat((char *)pkt->data, buf, 2048);

	pkt->cmd = APP_GET_GROUP_INFO;
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if (pkt)
		free(pkt);

	close(fd);

	return 0;
}

#ifdef _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT
static void __app_info_iter_limit_cb(void *user_data, const char *appid, const struct appinfo *ai)
{
	if(appinfo_get_boolean(ai, AIT_TASKMANAGE) && !appinfo_get_boolean(ai, AIT_COOLDOWN) ) {
		appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "blocking");
	}
}

static void __app_info_iter_release_cb(void *user_data, const char *appid, const struct appinfo *ai)
{
	if(appinfo_get_boolean(ai, AIT_TASKMANAGE) && !appinfo_get_boolean(ai, AIT_COOLDOWN) ) {
		appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "installed");
	}
}

static int __cooldown_cb(const char* status, void *data)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;
	const struct appinfo *ai;
	int dummy;

	_D("status %s", status);

	if(strncmp(status, "LimitAction", 11) == 0) {
		appinfo_foreach(_saf, __app_info_iter_limit_cb, NULL);
		for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
		{
			info_t = (app_status_info_t *)iter->data;
			ai = appinfo_find(_saf, info_t->appid);
			if(appinfo_get_boolean(ai, AIT_TASKMANAGE) && !appinfo_get_boolean(ai, AIT_COOLDOWN)) {
				appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "blocking");
				const char *type = appinfo_get_value(ai, AIT_COMPTYPE);
				aul_send_app_terminate_request_signal(info_t->pid, info_t->appid, info_t->pkgid, type);
				__app_send_raw_with_noreply(info_t->pid, APP_TERM_BY_PID_ASYNC, (unsigned char *)&dummy, sizeof(int) );
			}
		}
		cooldown_status = COOLDOWN_LIMIT;
	} else if (strncmp(status, "Release", 7) == 0 && cooldown_status != COOLDOWN_RELEASE){
		appinfo_foreach(_saf, __app_info_iter_release_cb, NULL);
		cooldown_status = COOLDOWN_RELEASE;
	}

	return 0;
}

int _status_get_cooldown_status(void)
{
	return cooldown_status;
}

#endif // _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT

#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
static void __app_info_iter_ups_release_cb(void *user_data, const char *appid, const struct appinfo *ai)
{
	const char *component = NULL;
	int onboot = 0;

	component = appinfo_get_value(ai, AIT_COMPTYPE);
	onboot = appinfo_get_boolean(ai, AIT_ONBOOT);
	if (onboot == 1 && strncmp(component, "svcapp", 6) == 0) {
		if (_status_app_is_running(appid) < 0) {
			_W("start service (ups release) - %s", appid);
			_start_srv(ai);
		} else {
			_E("service: %s is already running", appid);
		}
	}
}

static void __ups_cb(keynode_t *key, void *data)
{
	const char *name = NULL;
	int ups_mode = 0;

	name = vconf_keynode_get_name(key);
	if (name == NULL) {
		_E("vconf key value for UPS mode is invalid");
		return;
	} else if (strcmp(name, VCONFKEY_SETAPPL_PSMODE) == 0) {
		ups_mode = vconf_keynode_get_int(key);
		if (ups_mode == SETTING_PSMODE_NORMAL) {
			_W("UPS mode is disabled");
			appinfo_foreach(_saf, __app_info_iter_ups_release_cb, NULL);
		}
		else if (ups_mode == SETTING_PSMODE_EMERGENCY) {
			_W("UPS mode is enabled");
		}
		else {
			_W("Current Power Saving mode: %d", ups_mode);
		}
	}
}
#endif //_APPFW_FEATURE_ULTRA_POWER_SAVING_MODE

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
static int _status_log_init(void)
{
	int offset = 0;

	log_fd = open(AMD_LOG_FILE, O_CREAT | O_WRONLY, 0644);

	if(log_fd < 0)
		return -1;

	offset = lseek(log_fd, 0, SEEK_END);
	if (offset != 0) {
		log_index = (int)(offset / AMD_LOG_BUFFER_STRING_SIZE);

		if (log_index >= AMD_LOG_BUFFER_SIZE) {
			log_index = 0;
			lseek(log_fd, 0, SEEK_SET);
		}
	}

	return 0;
}

int _status_log_save(const char *tag, const char *message)
{
	int ret = 0;
	int offset = 0;
	time_t now;
	char time_buf[32] = {0,};
	char buffer[AMD_LOG_BUFFER_STRING_SIZE] = {0,};

	if(log_fd < 0)
		return -1;

	time(&now);
	ctime_r(&now, time_buf);
	if (log_index != 0) {
		offset = lseek(log_fd, 0, SEEK_CUR);
	} else {
		offset = lseek(log_fd, 0, SEEK_SET);
	}

	if (offset == -1)
		_E("error in lseek: %s", strerror(errno));

	snprintf(buffer, AMD_LOG_BUFFER_STRING_SIZE, "[%-6d] %-15s %-50s %s", log_index, tag, message, time_buf);

	ret = write(log_fd, buffer, strlen(buffer));
	if (ret < 0) {
		_E("Cannot write the amd log: %d", ret);
		return -1;
	}

	if (++log_index >= AMD_LOG_BUFFER_SIZE) {
		log_index = 0;
	}

	return 0;
}
#endif

int _status_init(struct amdmgr* amd)
{
	_saf = amd->af;

#ifdef _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT
	aul_listen_cooldown_signal(__cooldown_cb, NULL);
#endif // _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT

#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_PSMODE, __ups_cb, NULL) != 0) {
		_E("Unable to register callback for VCONFKEY_SETAPPL_PSMODE");
	}
#endif

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
	_status_log_init();
#endif

	return 0;
}

gboolean _status_check_window_ready(void)
{
	if (access(WINDOW_READY, R_OK) == 0)
		return true;
	else
		return false;
}
