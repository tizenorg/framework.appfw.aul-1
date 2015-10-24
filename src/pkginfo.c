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
#include <string.h>
#include <stdlib.h>

#include <pkgmgr-info.h>
#include <pkgmgrinfo_zone.h>
#include "aul.h"
#include "aul_api.h"
#include "menu_db_util.h"
#include "simple_util.h"
#include "app_sock.h"
#include "aul_util.h"
#include "aul_zone.h"

#define METADATA_LEGACY_LIFECYCLE "http://developer.samsung.com/tizen/metadata/legacylifecycle"

static const char *__appid = NULL;
static const char *__pkgid = NULL;
static int __aul_support_legacy_lifecycle = -1;

static int __get_pkgname_bypid(int pid, char *pkgname, int len);

SLPAPI int aul_app_get_pid(const char *appid)
{
	int ret = 0;

	if (appid == NULL)
		return 0;

	ret = __app_send_raw(AUL_UTIL_PID, APP_GET_PID, (unsigned char *)appid, strlen(appid));

	return ret;
}

SLPAPI int aul_app_get_pid_cache(const char *appid)
{
	int ret = 0;

	if (appid == NULL)
		return 0;

	ret = __app_send_raw(AUL_UTIL_PID, APP_GET_PID_CACHE, (unsigned char *)appid, strlen(appid));

	return ret;
}

SLPAPI int aul_app_get_last_caller_pid(int pid)
{
	int ret = 0;

	if (pid < 0)
		return 0;

	ret = __app_send_raw(AUL_UTIL_PID, APP_GET_LAST_CALLER_PID, (unsigned char *)&pid, sizeof(pid));

	return ret;
}

SLPAPI int aul_app_is_running(const char *appid)
{
	int ret = 0;

	if (appid == NULL)
		return 0;

	ret = __app_send_raw(AUL_UTIL_PID, APP_IS_RUNNING, (unsigned char*)appid, strlen(appid));

	if(ret > 0)
		return true;

	return 0;
}

SLPAPI int aul_app_get_running_app_info(aul_app_info_iter_fn iter_fn,
					void *user_param)
{
	return aul_get_running_app_info_from_memory(iter_fn, user_param);
}

SLPAPI int aul_get_running_app_info_from_proc(aul_app_info_iter_fn iter_fn,
					void *user_param)
{
	app_pkt_t *pkt = NULL;
	char *saveptr1, *saveptr2;
	char *token;
	char *pkt_data;
	aul_app_info info;

	memset(&info, 0, sizeof(info));
	if (iter_fn == NULL)
		return AUL_R_EINVAL;

	pkt = __app_send_cmd_with_result(AUL_UTIL_PID, APP_RUNNING_INFO, NULL, 0);

	if (pkt == NULL)
		return AUL_R_ERROR;

	for( pkt_data = (char *)pkt->data; ; pkt_data = NULL) {
		token = strtok_r(pkt_data, ";", &saveptr1);
		if (token == NULL)
			break;
		info.pid = atoi(strtok_r(token, ":", &saveptr2));
		info.appid = strtok_r(NULL, ":", &saveptr2);
		info.app_path = strtok_r(NULL, ":", &saveptr2);
		info.pkg_name = strdup(info.appid);

		iter_fn(&info, user_param);
		free(info.pkg_name);
	}

	free(pkt);

	return AUL_R_OK;
}

SLPAPI int aul_get_running_app_info_from_memory(aul_app_info_iter_fn iter_fn,
					void *user_param)
{
	app_pkt_t *pkt = NULL;
	char *saveptr1, *saveptr2;
	char *token;
	char *pkt_data;
	aul_app_info info;

	memset(&info, 0, sizeof(info));
	if (iter_fn == NULL)
		return AUL_R_EINVAL;

	pkt = __app_send_cmd_with_result(AUL_UTIL_PID, APP_RUNNING_INFO_MEMORY, NULL, 0);

	if (pkt == NULL)
		return AUL_R_ERROR;

	for( pkt_data = (char *)pkt->data; ; pkt_data = NULL) {
		token = strtok_r(pkt_data, ";", &saveptr1);
		if (token == NULL)
			break;
		info.pid = atoi(strtok_r(token, ":", &saveptr2));
		info.appid = strtok_r(NULL, ":", &saveptr2);
		info.app_path = strtok_r(NULL, ":", &saveptr2);
		info.pkg_name = strdup(info.appid);

		iter_fn(&info, user_param);
		free(info.pkg_name);
	}

	free(pkt);

	return AUL_R_OK;
}

SLPAPI void aul_set_preinit_appid(const char *appid)
{
	__appid = (char *)appid;
}

static const char* __aul_get_preinit_appid(void)
{
	return __appid;
}

SLPAPI void aul_set_preinit_pkgid(const char *pkgid)
{
	__pkgid = (char *)pkgid;
}

SLPAPI const char* aul_get_preinit_pkgid(void)
{
	return __pkgid;
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
	} else
		snprintf(pkgname, len, "%s", _get_pkgname(menu_info));

	free(cmdline);
	_free_app_info_from_db(menu_info);
	return 0;
}

SLPAPI int aul_app_get_pkgname_bypid(int pid, char *pkgname, int len)
{
	return aul_app_get_appid_bypid(pid, pkgname, len);
}

SLPAPI int aul_app_get_appid_bypid(int pid, char *appid, int len)
{
	app_pkt_t *pkt = NULL;
	int pgid;

	char oldZone[64] = { 0, };
	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);

	if (_cur_zone == NULL) {
		if (pid == getpid()) {
			const char *preinit_appid = __aul_get_preinit_appid();

			if (preinit_appid != NULL)
			{
				snprintf(appid, len > MAX_PACKAGE_STR_SIZE ? MAX_PACKAGE_STR_SIZE : len, "%s", preinit_appid);
				pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
				return AUL_R_OK;
			}
		}

		if (pid == getpid() || getuid()==0 || geteuid()==0) {
			if (__get_pkgname_bypid(pid, appid, len) == 0) {
				SECURE_LOGD("appid for %d is %s", pid, appid);
				pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
				return AUL_R_OK;
			}
			/* support app launched by shell script*/
			if (pid <= 0)
				return AUL_R_ERROR;

			pgid = getpgid(pid);
			if (pgid <= 1) {
				pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
				return AUL_R_ERROR;
			}

			_D("second change pgid = %d, pid = %d", pgid, pid);
			if (__get_pkgname_bypid(pgid, appid, len) == 0) {
				pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
				return AUL_R_OK;
			}

			pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
			return AUL_R_ERROR;
		}
	}

	if (appid == NULL) {
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return AUL_R_EINVAL;
	}

	pkt = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GET_APPID_BYPID, (unsigned char *)&pid, sizeof(pid));

	if(pkt == NULL) {
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return AUL_R_ERROR;
	}
	if(pkt->cmd == APP_GET_INFO_ERROR) {
		free(pkt);
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return AUL_R_ERROR;
	}

	snprintf(appid, len, "%s", pkt->data);
	free(pkt);
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
	return AUL_R_OK;
}

static int __get_pkgid_bypid(int pid, char *pkgid, int len)
{
	char *cmdline;
	app_info_from_db *menu_info;

	if (pid == getpid()) {
		const char *preinit_pkgid = aul_get_preinit_pkgid();
		if (preinit_pkgid != NULL) {
			snprintf(pkgid, len, "%s", preinit_pkgid);
			return AUL_R_OK;
		}
	}

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

SLPAPI int aul_app_get_pkgid_bypid(int pid, char *pkgid, int len)
{
	app_pkt_t *pkt = NULL;
	int pgid;
	char oldZone[64] = { 0, };

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
	if(pid == getpid() || getuid()==0 || geteuid()==0) {
		if (__get_pkgid_bypid(pid, pkgid, len) == 0) {
			SECURE_LOGD("pkgid for %d is %s", pid, pkgid);
			pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
			return AUL_R_OK;
		}
		/* support app launched by shell script*/

		pgid = getpgid(pid);
		if (pgid <= 1) {
			pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
			return AUL_R_ERROR;
		}

		_D("second change pgid = %d, pid = %d", pgid, pid);
		if (__get_pkgid_bypid(pgid, pkgid, len) == 0) {
			pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
			return AUL_R_OK;
		}

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return AUL_R_ERROR;
	}

	if (pkgid == NULL) {
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return AUL_R_EINVAL;
	}

	pkt = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GET_PKGID_BYPID, (unsigned char *)&pid, sizeof(pid));

	if(pkt == NULL) {
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return AUL_R_ERROR;
	}
	if(pkt->cmd == APP_GET_INFO_ERROR) {
		free(pkt);
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return AUL_R_ERROR;
	}
	snprintf(pkgid, len, "%s", pkt->data);
	free(pkt);
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

	return AUL_R_OK;
}

SLPAPI int aul_app_get_cmdline_bypid(int pid, char *cmdline, int len)
{
	app_pkt_t *pkt = NULL;

	if (cmdline == NULL)
		return AUL_R_EINVAL;

	pkt = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GET_CMDLINE, (unsigned char *)&pid, sizeof(pid));

	if(pkt == NULL)
		return AUL_R_ERROR;
	if(pkt->cmd == APP_GET_INFO_ERROR) {
		free(pkt);
		return AUL_R_ERROR;
	}

	snprintf(cmdline, len, "%s", pkt->data);
	_D("cmdline : %s", cmdline);
	free(pkt);
	return AUL_R_OK;
}

SLPAPI int aul_get_support_legacy_lifecycle(void)
{
	char oldZone[64] = { 0, };

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
	if (__aul_support_legacy_lifecycle != -1) {
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return __aul_support_legacy_lifecycle;
	}

	int ret = 0;
	pkgmgrinfo_appinfo_h handle = NULL;
	char *metadata_value = NULL;

	if (!__appid) {
		char appid[128] = {0,};

		ret = aul_app_get_appid_bypid(getpid(), appid, sizeof(appid));
		if (ret != AUL_R_OK) {
			_E("Failed to get appid");
			return 0;
		}

		__appid = strdup(appid);
	}

	ret = pkgmgrinfo_appinfo_get_appinfo(__appid, &handle);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return 0;
	}

	ret = pkgmgrinfo_appinfo_get_metadata_value(handle, METADATA_LEGACY_LIFECYCLE, &metadata_value);
	if (ret != PMINFO_R_OK) {
		__aul_support_legacy_lifecycle = 0;
	} else {
		__aul_support_legacy_lifecycle = 1;
	}

	pkgmgrinfo_appinfo_destroy_appinfo(handle);
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
	return __aul_support_legacy_lifecycle;
}

SLPAPI char *aul_get_group_info(void)
{
	app_pkt_t *pkt = NULL;
	char *result = NULL;
	int len = 0;

	pkt = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GET_GROUP_INFO, NULL, 0);
	if (pkt) {
		len = strlen((const char *)pkt->data);
		result = (char *)malloc(sizeof(char) * (len +1));
		if (result == NULL) {
			_E("Failed to allocate memory");
			free(pkt);
			return NULL;
		}
		strncpy(result, (const char *)pkt->data, len);
		result[len] = 0;
		free(pkt);
	}

	return result;
}
