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
#include <proc_stat.h>
#include <pkgmgr-info.h>
#ifdef _APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS
#include <Ecore_X.h>
#include <vconf/vconf.h>
#endif

#include "amd_config.h"
#include "amd_status.h"
#include "amd_appinfo.h"
#include "aul_util.h"
#include "simple_util.h"
#include "app_sock.h"
#include "menu_db_util.h"

GSList *app_status_info_list = NULL;
struct appinfomgr *_saf = NULL;

GHashTable *cooldown_tbl;

GHashTable *cooldown_black_tbl;

char *cooldown_list[] = {
};

char *cooldown_black_list[] = {
};

int cooldown_status = 0;

#define WHITE_LIST_COUNT 0
#define BLACK_LIST_COUNT 0

#ifdef _APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS
#define LCD_ON	"LCDOn"
#define LCD_OFF	"LCDOff"
#define PROC_SIZE	256
#define WAKE_UP_GESTURE_CLOCK		1
#endif

int _status_add_app_info_list(char *appid, char *app_path, const char *caller, int pid, int pad_pid)
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
	if (info_t == NULL) {
		_E("out of memory");
		return -1;
	}

	memset(info_t, 0, sizeof(app_status_info_t));

	strncpy(info_t->appid, appid, MAX_PACKAGE_STR_SIZE-1);
	strncpy(info_t->app_path, app_path, MAX_PACKAGE_APP_PATH_SIZE-1);
	if(caller)
		strncpy(info_t->caller, caller, MAX_PACKAGE_STR_SIZE-1);
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

char* _status_get_caller_by_appid(const char *appid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if( strncmp(appid, info_t->appid, MAX_PACKAGE_STR_SIZE-1) == 0) {
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
	int len;
	char tmp_pid[MAX_PID_STR_BUFSZ];

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(!pkt) {
		_E("malloc fail");
		close(fd);
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
	const char *ae;
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
	if (apppath == NULL) {
		_E("out of memory");
		return -1;
	}

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
	int len;
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
	int len;
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

int _status_get_cmdline(int fd, int pid)
{
	app_pkt_t *pkt = NULL;
	int len;
	int pgid;
	char *cmdline;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(!pkt) {
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

	snprintf((char *)pkt->data, MAX_PACKAGE_STR_SIZE, cmdline);
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


static void __app_info_iter_limit_cb(void *user_data, const char *appid, const struct appinfo *ai)
{
	if(!g_hash_table_lookup(cooldown_tbl, appid)) {
		appinfo_set_value(ai, AIT_STATUS, "blocking");
	}
}

static void __app_info_iter_waring_cb(void *user_data, const char *appid, const struct appinfo *ai)
{
	if(g_hash_table_lookup(cooldown_black_tbl, appid)) {
		appinfo_set_value(ai, AIT_STATUS, "blocking");
	}
}

static void __app_info_iter_release_cb(void *user_data, const char *appid, const struct appinfo *ai)
{
	const char *component = NULL;
	int onboot = 0;
	int restart = 0;

	if(!g_hash_table_lookup(cooldown_tbl, appid)) {
		component = appinfo_get_value(ai, AIT_COMPTYPE);
		onboot = appinfo_get_boolean(ai, AIT_ONBOOT);
		restart = appinfo_get_boolean(ai, AIT_RESTART);
		if (onboot == 1 && restart == 1 && component && strncmp(component, "svcapp", 6) == 0)
		{
			if (_status_app_is_running(appid) < 0)
			{
				_I("start service (cooldown release) - %s", appid);
				_start_srv(ai, NULL);
			}
			else
			{
				_E("service: %s is already running", appid);
			}
		}
		appinfo_set_value(ai, AIT_STATUS, "installed");
	}
}



static int __cooldown_cb(const char* status, void *data)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;
	int ret;
	int dummy;

	_I("__cooldown_cb, status: %s", status);

	if(strncmp(status, "LimitAction", 11) == 0) {
		appinfo_foreach(_saf, __app_info_iter_limit_cb, NULL);
		for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
		{
			info_t = (app_status_info_t *)iter->data;
			if(!g_hash_table_lookup(cooldown_tbl, info_t->appid)) {
				proc_group_change_status(PROC_CGROUP_SET_TERMINATE_REQUEST, info_t->pid, NULL);
				ret = __app_send_raw_with_noreply(info_t->pid, APP_TERM_BY_PID_ASYNC, (unsigned char *)&dummy, sizeof(int) );
			}
		}
		cooldown_status = COOLDOWN_LIMIT;
	} else if(strncmp(status, "WarningAction", 13) == 0) {
		appinfo_foreach(_saf, __app_info_iter_waring_cb, NULL);
		for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
		{
			info_t = (app_status_info_t *)iter->data;
			if(g_hash_table_lookup(cooldown_black_tbl, info_t->appid)) {
				proc_group_change_status(PROC_CGROUP_SET_TERMINATE_REQUEST, info_t->pid, NULL);
				ret = __app_send_raw_with_noreply(info_t->pid, APP_TERM_BY_PID_ASYNC, (unsigned char *)&dummy, sizeof(int) );
			}
		}
		cooldown_status = COOLDOWN_WARNING;
	} else if (strncmp(status, "Release", 7) == 0){
		appinfo_foreach(_saf, __app_info_iter_release_cb, NULL);
		cooldown_status = COOLDOWN_RELEASE;
	}

	return 0;
}

int _status_get_cooldown_status(void)
{
	return cooldown_status;
}

#ifdef _APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS
static int __lcd_status_cb(const char *lcd_status, void *data)
{
	int gesture = -1;
	Ecore_X_Window win;
	int pid = 0;
	bundle *kb = NULL;
	char proc_file[PROC_SIZE] = {0, };
	static int paused_pid = 0;

	// Check the wake-up gesture is a clock or not.
	// 0: Off, 1: Clock, 2: Last viewed screen
	if (vconf_get_int(VCONFKEY_WMS_WAKEUP_BY_GESTURE_SETTING, &gesture) < 0) {
		_E("Failed to get VCONFKEY_WMS_WAKEUP_BY_GESTURE_SETTING");
		return 0;
	}

	if (gesture == WAKE_UP_GESTURE_CLOCK) {
		SECURE_LOGD("Skip when wake-up gesture is a Clock.");
		return 0;
	}

	// Get the topmost app
	win = ecore_x_window_focus_get();
	if (ecore_x_netwm_pid_get(win, &pid) != 1) {
		_E("Can't get pid for focus x window (%x)", win);
		return 0;
	}
	SECURE_LOGD("The topmost app's pid is %d.", pid);

	// Pause or Resume the app when the lcd becomes On/Off
	if (lcd_status && (strncmp(lcd_status, LCD_OFF, strlen(LCD_OFF)) == 0)) {
		SECURE_LOGD("LCD status becomes Off. Pause the topmose app, %d", pid);
		paused_pid = pid;
		kb = bundle_create();
		app_send_cmd_with_noreply(pid, APP_PAUSE_LCD_OFF, kb);
	}
	else if (lcd_status && (strncmp(lcd_status, LCD_ON, strlen(LCD_ON)) == 0)) {
		if (paused_pid != pid) {
			SECURE_LOGE("The topmost app(%d) is different with the paused app(%d).", pid, paused_pid);
		}

		// Check whether the paused app is running or Not
		snprintf(proc_file, PROC_SIZE, "/proc/%d/cmdline", paused_pid);
		if (access(proc_file, F_OK) != 0) {
			SECURE_LOGE("paused app(%d) seems to be killed.", paused_pid);
			if (paused_pid != pid) {
				paused_pid = pid;
			} else {
				return 0;
			}
		}

		SECURE_LOGD("LCD status becomes On. Resume the paused app, %d", paused_pid);
		kb = bundle_create();
		app_send_cmd_with_noreply(paused_pid, APP_RESUME_LCD_ON, kb);
	}
	else {
		_E("Invalid input param for lcd_status.");
	}

	bundle_free(kb);
	return 0;
}
#endif

static int __app_info_handler (const pkgmgrinfo_appinfo_h handle, void *data)
{
	char *tmp_appid;
	char *appid;

	pkgmgrinfo_appinfo_get_appid(handle, &tmp_appid);

	appid = strdup(tmp_appid);

	g_hash_table_insert(cooldown_tbl, appid, appid);

	SECURE_LOGD("white_list : %s", appid);

	return 0;
}

static int __blacklist_app_info_handler (const pkgmgrinfo_appinfo_h handle, void *data)
{
	char *tmp_appid;
	char *appid;

	pkgmgrinfo_appinfo_get_appid(handle, &tmp_appid);

	appid = strdup(tmp_appid);

	g_hash_table_insert(cooldown_black_tbl, appid, appid);

	SECURE_LOGD("white_list : %s", appid);

	return 0;
}

int _status_init(struct amdmgr* amd)
{
	int i;
	pkgmgrinfo_appinfo_h handle = NULL;

	_saf = amd->af;

	aul_listen_cooldown_signal(__cooldown_cb, NULL);

	cooldown_tbl = g_hash_table_new(g_str_hash, g_str_equal);
	for(i = 0; i < WHITE_LIST_COUNT; i++) {
		SECURE_LOGD("pkgid %s", cooldown_list[i]);
		if (pkgmgrinfo_pkginfo_get_pkginfo(cooldown_list[i], &handle) == PMINFO_R_OK){
			pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __app_info_handler, NULL);
			pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __app_info_handler, NULL);
			pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		}
	}

	cooldown_black_tbl = g_hash_table_new(g_str_hash, g_str_equal);
	for(i = 0; i < BLACK_LIST_COUNT; i++) {
		SECURE_LOGD("pkgid %s", cooldown_black_list[i]);
		if (pkgmgrinfo_pkginfo_get_pkginfo(cooldown_black_list[i], &handle) == PMINFO_R_OK){
			pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __blacklist_app_info_handler, NULL);
			pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __blacklist_app_info_handler, NULL);
			pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		}
	}

#ifdef _APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS
	// Register callback for LCD On/Off
	aul_listen_lcd_status_signal(__lcd_status_cb, NULL);
#endif
	return 0;
}

