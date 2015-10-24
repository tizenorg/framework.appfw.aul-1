/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <unistd.h>
#include <linux/limits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pkgmgr-info.h>
#include <pkgmgrinfo_zone.h>

#include "aul_api.h"
#include "aul_util.h"
#include "simple_util.h"
#include "aul.h"
#include "aul_zone.h"

#define _MAX_PACKAGE_ID_LEN 256
#define _MAX_BASE_PATH_LEN 512

static const char _EXTERNAL_APP_SPECIFIC_PATH[] = "/opt/storage/sdcard/apps/";
static const char _APP_SPECIFIC_PATH[] = "/opt/usr/apps/";
static const char _PRELOADED_APP_SPECIFIC_PATH[] = "/usr/apps/";

static const char _DATA_DIR[] = "data/";
static const char _CACHE_DIR[] = "cache/";
static const char _RESOURCE_DIR[] = "res/";
static const char _TEP_RESOURCE_DIR[] = "res/tep/";
static const char _SHARED_DATA_DIR[] = "shared/data/";
static const char _SHARED_TRUSTED_DIR[] = "shared/trusted/";
static const char _SHARED_RESOURCE_DIR[] = "shared/res/";

static char external_root_path[_MAX_BASE_PATH_LEN] = {0,};
static char root_path[_MAX_BASE_PATH_LEN] = {0,};
static char data_path[_MAX_BASE_PATH_LEN] = {0,};
static char cache_path[_MAX_BASE_PATH_LEN] = {0,};
static char resource_path[_MAX_BASE_PATH_LEN] = {0,};
static char tep_resource_path[_MAX_BASE_PATH_LEN] = {0,};
static char shared_data_path[_MAX_BASE_PATH_LEN] = {0,};
static char shared_resource_path[_MAX_BASE_PATH_LEN] = {0,};
static char shared_trusted_path[_MAX_BASE_PATH_LEN] = {0,};
static char external_data_path[_MAX_BASE_PATH_LEN] = {0,};
static char external_cache_path[_MAX_BASE_PATH_LEN] = {0,};
static char external_shared_data_path[_MAX_BASE_PATH_LEN] = {0,};
static char pkgid[_MAX_PACKAGE_ID_LEN] = {0,};

static int __get_pkgid_by_appid(char *pkgid, int pkgid_len, const char *appid)
{
	pkgmgrinfo_appinfo_h handle = NULL;
	char *tmp_pkgid = NULL;

	// get pkginfo handle
	int err = pkgmgrinfo_appinfo_get_appinfo(appid, &handle);
	if (err != PMINFO_R_OK) {
		_E("Failed to get app info. (err:%d)", err);
		return AUL_R_ENOAPP;
	}

	// get and set pkgid
	err = pkgmgrinfo_appinfo_get_pkgid(handle, &tmp_pkgid);
	if (err != PMINFO_R_OK) {
		_E("Failed to get pkgid. (err:%d)", err);
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return AUL_R_ENOAPP;
	}
	strncpy(pkgid, tmp_pkgid, pkgid_len);
	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return AUL_R_OK;
}

static int __get_pkgid(char* pkgid, int pkgid_len)
{
	char appid[_MAX_PACKAGE_ID_LEN] = {0,};
	const char *preinit_pkgid = NULL;

	preinit_pkgid = aul_get_preinit_pkgid();
	if (preinit_pkgid != NULL) {
		strncpy(pkgid, preinit_pkgid, pkgid_len);
		return AUL_R_OK;
	}

	// get appid
	int err = aul_app_get_appid_bypid(getpid(), appid, _MAX_PACKAGE_ID_LEN - 1);
	if (err != AUL_R_OK) {
		_E("Failed to get appid. (err:%d)", err);
		return err;
	}

	return __get_pkgid_by_appid(pkgid, pkgid_len, appid);
}

static const char* __get_app_specific_path(const char *pkgid)
{
	pkgmgrinfo_pkginfo_h handle;
	int ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK)
		return NULL;

	bool preload;
	ret = pkgmgrinfo_pkginfo_is_preload(handle, &preload);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return NULL;
	}

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	if (preload) {
		return _PRELOADED_APP_SPECIFIC_PATH;
	}

	return _APP_SPECIFIC_PATH;
}

static int __get_root_path(char *root_path, int root_path_len, bool external,
                           bool can_write)
{
	char pkgid[_MAX_PACKAGE_ID_LEN] = {0,};
	const char *specific_path = NULL;

	int err = __get_pkgid(pkgid, _MAX_PACKAGE_ID_LEN - 1);
	if (err != AUL_R_OK) {
		return err;
	}

	if (can_write)
		specific_path = external ? _EXTERNAL_APP_SPECIFIC_PATH : _APP_SPECIFIC_PATH;
	else {
		specific_path = external ? _EXTERNAL_APP_SPECIFIC_PATH : __get_app_specific_path(pkgid);
		if (specific_path == NULL) {
			_E("out of memory");
			return AUL_R_ERROR;
		}
	}

	int specific_path_len = strlen(specific_path);
	int pkgid_len = strlen(pkgid);
	int total_len = specific_path_len + pkgid_len + 1;

	if (total_len > root_path_len) {
		_E("Assert: path length %d is too long", total_len);
		assert(false);
	}

	strncat(root_path, specific_path, specific_path_len);
	strncat(root_path + specific_path_len, pkgid, pkgid_len);
	root_path[specific_path_len + pkgid_len] = '/';
	root_path[specific_path_len + pkgid_len + 1] = '\0';

	return AUL_R_OK;
}

static char* __get_base_path(bool can_write)
{
	static char base_path[_MAX_BASE_PATH_LEN] = {0,};

	base_path[0] = '\0';
	if (__get_root_path(base_path, _MAX_BASE_PATH_LEN - 1, false,
	                    can_write) != AUL_R_OK)
		return NULL;

	return base_path;
}

static int __get_path(char *path, int path_len, const char *dir_name,
                      bool external, bool can_write)
{
	char* root_path = NULL;
	pkgmgrinfo_pkginfo_h pkginfo = NULL;
	int is_res = 0;

	if (dir_name == NULL)
	{
		_E("Assert: dir name is NULL!");
		assert(false);
	}
	else if (strncmp(dir_name, _RESOURCE_DIR, strlen(_RESOURCE_DIR)) == 0 ||
			strncmp(dir_name, _SHARED_RESOURCE_DIR, strlen(_SHARED_RESOURCE_DIR)) == 0)
	{
		char pkgid[_MAX_PACKAGE_ID_LEN] = {0,};
		if (__get_pkgid(pkgid, _MAX_PACKAGE_ID_LEN - 1) != AUL_R_OK)
		{
			_E("Assert: failed to get the package id!");
			assert(false);
		}

		if (pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkginfo) != PMINFO_R_OK)
		{
			_E("Failed to get the package info from pkgid!");
			return AUL_R_ERROR;
		}

		if (pkgmgrinfo_pkginfo_get_root_path(pkginfo, &root_path) != PMINFO_R_OK)
		{
			_E("Failed to get the root path from pkginfo!");
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
			return AUL_R_ERROR;
		}

		is_res = 1;
	}
	else
	{
		root_path = (char *) (external ? aul_get_app_external_root_path() :
			__get_base_path(can_write));
		if (root_path == NULL)
		{
			_E("root_path is NULL!");
			return AUL_R_ERROR;
		}
	}

	int dir_name_len = strlen(dir_name);
	int root_path_len = strlen(root_path);
	int total_len = root_path_len + dir_name_len;

	if (total_len > path_len)
	{
		_E("Assert: path length %d is too long", total_len);
		assert(false);
	}

	strncpy(path, root_path, root_path_len);
	if (is_res)
	{
		strncat(path, "/", 1);
		++root_path_len;
	}
	strncpy(path + root_path_len, dir_name, dir_name_len);

	if (pkginfo != NULL)
	{
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
	}

	return AUL_R_OK;
}

static int __get_path_by_appid(char **path, const char *appid,
                               const char *dir_name, bool external)
{
	if (dir_name == NULL) {
		_E("Assert: dir name is NULL!");
		assert(false);
	}

	if (path == NULL || appid == NULL) {
		return AUL_R_EINVAL;
	}

	pkgmgrinfo_pkginfo_h pkginfo = NULL;
	char *specific_path = NULL;
	int total_len = 0;

	char pkgid[_MAX_PACKAGE_ID_LEN] = {0,};
	int err = __get_pkgid_by_appid(pkgid, _MAX_PACKAGE_ID_LEN - 1, appid);
	if (err != AUL_R_OK) {
		return err;
	}

	if (strncmp(dir_name, _RESOURCE_DIR, strlen(_RESOURCE_DIR)) == 0 ||
		strncmp(dir_name, _SHARED_RESOURCE_DIR, strlen(_SHARED_RESOURCE_DIR)) == 0) {
		if (pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkginfo) != PMINFO_R_OK) {
			_E("Failed to get the package info from pkgid!");
			return AUL_R_ERROR;
		}

		if (pkgmgrinfo_pkginfo_get_root_path(pkginfo, &specific_path) != PMINFO_R_OK) {
			_E("Failed to get the root path from pkginfo!");
			pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
			return AUL_R_ERROR;
		}

		total_len = strlen(specific_path) + strlen(dir_name) + 1;

	} else {
		specific_path = (char *) (external ? _EXTERNAL_APP_SPECIFIC_PATH : _APP_SPECIFIC_PATH);
		total_len = strlen(specific_path) + strlen(pkgid) + 1 + strlen(dir_name);
	}

	if (total_len > _MAX_BASE_PATH_LEN - 1) {
		_E("Assert: path length %d is too long", total_len);
		assert(false);
	}

	*path = (char *)calloc(total_len + 1, sizeof(char));
	if (*path == NULL) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
		return AUL_R_ERROR;
	}

	if (pkginfo != NULL) {
		snprintf(*path, total_len + 1, "%s/%s", specific_path, dir_name);
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
	} else {
		snprintf(*path, total_len + 1, "%s%s/%s", specific_path, pkgid, dir_name);
	}

	return AUL_R_OK;
}

void _clear_path_cache(void)
{
	external_root_path[0] = '\0';
	root_path[0] = '\0';
	data_path[0] = '\0';
	cache_path[0] = '\0';
	resource_path[0] = '\0';
	shared_data_path[0] = '\0';
	shared_resource_path[0] = '\0';
	shared_trusted_path[0] = '\0';
	external_data_path[0] = '\0';
	external_cache_path[0] = '\0';
	external_shared_data_path[0] = '\0';
	pkgid[0] = '\0';
}

SLPAPI const char *aul_get_app_external_root_path(void)
{
	if (external_root_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_root_path(external_root_path, _MAX_BASE_PATH_LEN - 1, true,
		                          false);
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		if (ret != AUL_R_OK)
			return NULL;
	}

	return external_root_path;
}

SLPAPI const char *aul_get_app_root_path(void)
{
	if (root_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_root_path(root_path, _MAX_BASE_PATH_LEN - 1, false, false);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;
	}
	return root_path;
}

SLPAPI const char *aul_get_app_data_path(void)
{
	if (data_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(data_path, _MAX_BASE_PATH_LEN - 1, _DATA_DIR, false, true);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;
	}
	return data_path;
}

SLPAPI const char *aul_get_app_cache_path(void)
{
	if (cache_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(cache_path, _MAX_BASE_PATH_LEN - 1, _CACHE_DIR, false,
		                     true);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;
	}
	return cache_path;
}

SLPAPI const char *aul_get_app_resource_path(void)
{
	if (resource_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(resource_path, _MAX_BASE_PATH_LEN - 1, _RESOURCE_DIR,
		                     false,
		                     false);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;
	}
	return resource_path;
}

SLPAPI const char *aul_get_app_tep_resource_path(void)
{
	if (tep_resource_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(tep_resource_path, _MAX_BASE_PATH_LEN - 1, _TEP_RESOURCE_DIR,
		                     false,
		                     false);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;
	}
	return tep_resource_path;
}

SLPAPI const char *aul_get_app_shared_data_path(void)
{
	if (shared_data_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(shared_data_path, _MAX_BASE_PATH_LEN - 1, _SHARED_DATA_DIR,
		                     false, true);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;

	}
	return shared_data_path;
}

SLPAPI const char *aul_get_app_shared_resource_path(void)
{
	if (shared_resource_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(shared_resource_path, _MAX_BASE_PATH_LEN - 1,
		                     _SHARED_RESOURCE_DIR, false, false);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;
	}
	return shared_resource_path;
}

SLPAPI const char *aul_get_app_shared_trusted_path(void)
{
	if (shared_trusted_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(shared_trusted_path, _MAX_BASE_PATH_LEN - 1,
		                     _SHARED_TRUSTED_DIR, false, true);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;

	}
	return shared_trusted_path;
}

SLPAPI const char *aul_get_app_external_data_path(void)
{
	if (external_data_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(external_data_path, _MAX_BASE_PATH_LEN - 1, _DATA_DIR,
		                     true,
		                     true);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;

	}
	return external_data_path;
}

SLPAPI const char *aul_get_app_external_cache_path(void)
{
	if (external_cache_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(external_cache_path, _MAX_BASE_PATH_LEN - 1, _CACHE_DIR,
		                     true,
		                     true);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;

	}
	return external_cache_path;
}

SLPAPI const char *aul_get_app_external_shared_data_path(void)
{
	if (external_shared_data_path[0] == '\0') {
		char oldZone[64] = { 0, };

		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int ret = __get_path(external_shared_data_path, _MAX_PACKAGE_ID_LEN - 1,
		                     _SHARED_DATA_DIR, true, true);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if ( ret != AUL_R_OK)
			return NULL;

	}
	return external_shared_data_path;
}

SLPAPI const char *aul_get_app_specific_path(void)
{
	const char *specific_path = NULL;
	char oldZone[64] = { 0, };

	if (pkgid[0] == '\0') {
		pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
		int err = __get_pkgid(pkgid, _MAX_PACKAGE_ID_LEN - 1);

		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

		if (err != AUL_R_OK) {
			return NULL;
		}
	}

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
	specific_path = __get_app_specific_path(pkgid);
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

	return specific_path;
}

SLPAPI const char *aul_get_app_external_specific_path(void)
{
	return _EXTERNAL_APP_SPECIFIC_PATH;
}

SLPAPI int aul_get_app_shared_data_path_by_appid(const char *appid, char **path)
{
	char oldZone[64] = { 0, };

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
	int ret = __get_path_by_appid(path, appid, _SHARED_DATA_DIR, false);
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

	return ret;
}

SLPAPI int aul_get_app_shared_resource_path_by_appid(const char *appid,
        char **path)
{
	char oldZone[64] = { 0, };

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
	int ret = __get_path_by_appid(path, appid, _SHARED_RESOURCE_DIR, false);
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

	return ret;
}

SLPAPI int aul_get_app_shared_trusted_path_by_appid(const char *appid,
        char **path)
{
	char oldZone[64] = { 0, };

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
	int ret = __get_path_by_appid(path, appid, _SHARED_TRUSTED_DIR, false);
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

	return ret;
}

SLPAPI int aul_get_app_external_shared_data_path_by_appid(const char *appid,
        char **path)
{
	char oldZone[64] = { 0, };

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
	int ret = __get_path_by_appid(path, appid, _SHARED_DATA_DIR, true);
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);

	return ret;
}

SLPAPI char *aul_get_cmdline_bypid(int pid)
{
	return __proc_get_cmdline_bypid(pid);
}

