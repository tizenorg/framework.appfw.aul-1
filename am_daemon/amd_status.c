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

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <aul.h>
#include <string.h>
#include <Ecore.h>

#include "amd_config.h"
#include "amd_status.h"
#include "amd_appinfo.h"
#include "aul_util.h"
#include "simple_util.h"
#include "app_sock.h"
#include "menu_db_util.h"

GSList *app_status_info_list = NULL;

struct appinfomgr *_saf = NULL;

int _status_add_app_info_list(char *appid, char *app_path, int pid, int pad_pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid) {
			return 0;
		}
	}

	info_t = malloc(sizeof(app_status_info_t));
	strncpy(info_t->appid, appid, MAX_PACKAGE_STR_SIZE-1);
	strncpy(info_t->app_path, app_path, MAX_PACKAGE_APP_PATH_SIZE-1);
	info_t->status = STATUS_LAUNCHING;
	info_t->pid = pid;
	info_t->pad_pid = pad_pid;
	app_status_info_list = g_slist_append(app_status_info_list, info_t);

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		//SECURE_LOGD("%s, %d, %d", info_t->appid, info_t->pid, info_t->status);
	}

	return 0;
}

static Eina_Bool __app_terminate_timer_cb(void *data)
{
	int pid = (int)data;
	int ret = 0;

	_D("pid(%d)", pid);

	ret = kill(pid, SIGKILL);
	if (ret == -1)
		_D("send SIGKILL: %s", strerror(errno));

	return ECORE_CALLBACK_CANCEL;
}

int _status_update_app_info_list(int pid, int status)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid) {
			info_t->status = status;
			if(status == STATUS_DYING) {
				if(info_t->pad_pid != DEBUG_LAUNCHPAD_PID)
					ecore_timer_add(2, __app_terminate_timer_cb, info_t->pid);
			}
			break;
		}
	}

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		//SECURE_LOGD("%s, %d, %d", info_t->appid, info_t->pid, info_t->status);
	}

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
			app_status_info_list = g_slist_remove(app_status_info_list, info_t);
			free(info_t);
			break;
		}
	}

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		//SECURE_LOGD("%s, %d, %d", info_t->appid, info_t->pid, info_t->status);
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

	return -1;
}


int _status_app_is_running(char *appid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if( strncmp(appid, info_t->appid, MAX_PACKAGE_STR_SIZE) == 0 ) {
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

int _status_send_running_appinfo(int fd)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;
	app_pkt_t *pkt = NULL;
	int len;
	char tmp_pid[MAX_PID_STR_BUFSZ];

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(!pkt) {
		_E("malloc fail");
		return 0;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
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

	if ((len = send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if(pkt)
		free(pkt);

	close(fd);

	return 0;
}

int _status_app_is_running_v2(char *appid)
{
	char *apppath = NULL;
	int ret = 0;
	int i = 0;
	const struct appinfo *ai;

	if(appid == NULL)
		return -1;

	ai = appinfo_find(_saf, appid);

	if(ai == NULL)
		return -1;

	apppath = strdup(appinfo_get_value(ai, AIT_EXEC));

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

static int __get_pkginfo(const char *dname, const char *cmdline, void *priv)
{
	app_info_from_db *menu_info;
	char *r_info;

	r_info = (char *)priv;

	if ((menu_info = _get_app_info_from_db_by_apppath(cmdline)) == NULL)
		goto out;
	else {
		strncat(r_info, dname, 8);
		strncat(r_info, ":", 1);
		strncat(r_info, _get_pkgname(menu_info), MAX_PACKAGE_STR_SIZE);
		strncat(r_info, ":", 1);
		strncat(r_info, _get_app_path(menu_info), MAX_PACKAGE_APP_PATH_SIZE);
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
	int len;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	__proc_iter_cmdline(__get_pkginfo, pkt->data);

	pkt->cmd = APP_RUNNING_INFO_RESULT;
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((len = send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if(pkt)
		free(pkt);

	close(fd);

	return 0;
}

static int __get_pkgname_bypid(int pid, char *pkgname, int len)
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
	int len;
	int pgid;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = APP_GET_APPID_BYPID_ERROR;

	if (__get_pkgname_bypid(pid, (char *)pkt->data, MAX_PACKAGE_STR_SIZE) == 0) {
		SECURE_LOGD("appid for %d is %s", pid, pkt->data);
		pkt->cmd = APP_GET_APPID_BYPID_OK;
		goto out;
	}
	/* support app launched by shell script*/
	_D("second chance");
	pgid = getpgid(pid);
	if (pgid <= 1)
		goto out;

	_D("second change pgid = %d, pid = %d", pgid, pid);
	if (__get_pkgname_bypid(pgid, (char *)pkt->data, MAX_PACKAGE_STR_SIZE) == 0)
		pkt->cmd = APP_GET_APPID_BYPID_OK;

 out:
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((len = send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if(pkt)
		free(pkt);

	close(fd);

	return 0;
}


int _status_init(struct amdmgr* amd)
{
	_saf = amd->af;

	return 0;
}

