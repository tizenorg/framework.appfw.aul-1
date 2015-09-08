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

#include <unistd.h>
#include <linux/limits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pkgmgr-info.h>

#include "aul_api.h"
#include "aul_util.h"
#include "simple_util.h"
#include "aul.h"

#define _MAX_PACKAGE_ID_LEN 256
#define _MAX_BASE_PATH_LEN 512

static const char _EXTERNAL_APP_SPECIFIC_PATH[] = "/opt/storage/sdcard/apps/";
static const char _APP_SPECIFIC_PATH[] = "/opt/usr/apps/";

static const char _DATA_DIR[] = "data/";
static const char _CACHE_DIR[] = "cache/";
static const char _RESOURCE_DIR[] = "res/";
static const char _SHARED_DATA_DIR[] = "shared/data/";
static const char _SHARED_TRUSTED_DIR[] = "shared/trusted/";
static const char _SHARED_RESOURCE_DIR[] = "shared/res/";

static int __get_pkgid_by_appid(char *pkgid, int pkgid_len, const char *appid)
{
	pkgmgrinfo_appinfo_h handle = NULL;
	char *tmp_pkgid = NULL;

	// get pkginfo handle
	int err = pkgmgrinfo_appinfo_get_appinfo(appid, &handle);
	if (err != PMINFO_R_OK)
	{
		_E("Failed to get app info. (err:%d)", err);
		return AUL_R_ENOAPP;
	}

	// get and set pkgid
	err = pkgmgrinfo_appinfo_get_pkgid(handle, &tmp_pkgid);
	if (err != PMINFO_R_OK)
	{
		_E("Failed to get pkgid. (err:%d)", err);
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return AUL_R_ENOAPP;
	}

	strncat(pkgid, tmp_pkgid, pkgid_len);
	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return AUL_R_OK;
}

static int __get_pkgid(char* pkgid, int pkgid_len)
{
	char appid[_MAX_PACKAGE_ID_LEN] = {0,};

	// get appid
	int err = aul_app_get_appid_bypid(getpid(), appid, _MAX_PACKAGE_ID_LEN - 1);
	if (err != AUL_R_OK)
	{
		_E("Failed to get appid. (err:%d)", err);
		return err;
	}

	return __get_pkgid_by_appid(pkgid, pkgid_len, appid);
}

static int __get_root_path(char *root_path, int root_path_len, bool external)
{
	static char pkgid[_MAX_PACKAGE_ID_LEN] = {0,};
	const char *specific_path = external ? _EXTERNAL_APP_SPECIFIC_PATH : _APP_SPECIFIC_PATH;

	if (pkgid[0] == '\0')
	{
		int err = __get_pkgid(pkgid, _MAX_PACKAGE_ID_LEN - 1);
		if (err != AUL_R_OK)
		{
			return err;
		}
	}
	{
		int specific_path_len = strlen(specific_path);
		int pkgid_len = strlen(pkgid);
		int total_len = specific_path_len + pkgid_len + 1;

		if (total_len > root_path_len)
		{
			_E("Assert: path length %d is too long", total_len);
			assert(false);
		}

		strncat(root_path, specific_path, specific_path_len);
		strncat(root_path + specific_path_len, pkgid, pkgid_len);
		root_path[specific_path_len + pkgid_len] = '/';
	}

	return AUL_R_OK;
}

static int __get_path(char *path, int path_len, const char *dir_name, bool external)
{
	if (dir_name == NULL)
	{
		_E("Assert: dir name is NULL!");
		assert(false);
	}
	{
		const char *root_path = external ? aul_get_app_external_root_path() : aul_get_app_root_path();
		if (root_path == NULL)
		{
			return AUL_R_ERROR;
		}
		else
		{
			int dir_name_len = strlen(dir_name);
			int root_path_len = strlen(root_path);
			int total_len = root_path_len + dir_name_len;

			if (total_len > path_len)
			{
				_E("Assert: path length %d is too long", total_len);
				assert(false);
			}

			strncpy(path, root_path, root_path_len);
			strncpy(path + root_path_len, dir_name, dir_name_len);
		}
	}

	return AUL_R_OK;
}

static int __get_path_by_appid(char **path, const char *appid, const char *dir_name, bool external)
{
	if (dir_name == NULL)
	{
		_E("Assert: dir name is NULL!");
		assert(false);
	}

	if (path == NULL || appid == NULL)
	{
		return AUL_R_EINVAL;
	}

	{
		char pkgid[_MAX_PACKAGE_ID_LEN] = {0,};
		int err = __get_pkgid_by_appid(pkgid, _MAX_PACKAGE_ID_LEN - 1, appid);
		if (err != AUL_R_OK)
		{
			return err;
		}
		{
			const char *specific_path = external ? _EXTERNAL_APP_SPECIFIC_PATH : _APP_SPECIFIC_PATH;
			int specific_path_len = strlen(specific_path);
			int pkgid_len = strlen(pkgid);
			int dir_name_len = strlen(dir_name);
			int total_len = specific_path_len + pkgid_len + 1 + dir_name_len;

			if (total_len > _MAX_BASE_PATH_LEN - 1)
			{
				_E("Assert: path length %d is too long", total_len);
				assert(false);
			}

			*path = (char *)calloc(total_len + 1, sizeof(char));
			if (*path == NULL)
			{
				return AUL_R_ERROR;
			}

			snprintf(*path, total_len + 1, "%s%s/%s", specific_path, pkgid, dir_name);
		}
	}

	return AUL_R_OK;
}

SLPAPI const char *aul_get_app_external_root_path(void)
{
	static char external_root_path[_MAX_BASE_PATH_LEN] = {0,};
	if (external_root_path[0] == '\0')
	{
		if (__get_root_path(external_root_path, _MAX_BASE_PATH_LEN - 1, true) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return external_root_path;
}

SLPAPI const char *aul_get_app_root_path(void)
{
	static char root_path[_MAX_BASE_PATH_LEN] = {0,};
	if (root_path[0] == '\0')
	{
		if (__get_root_path(root_path, _MAX_BASE_PATH_LEN - 1, false) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return root_path;
}

SLPAPI const char *aul_get_app_data_path(void)
{
	static char data_path[_MAX_BASE_PATH_LEN] = {0,};
	if (data_path[0] == '\0')
	{
		if (__get_path(data_path, _MAX_BASE_PATH_LEN - 1, _DATA_DIR, false) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return data_path;
}

SLPAPI const char *aul_get_app_cache_path(void)
{
	static char cache_path[_MAX_BASE_PATH_LEN] = {0,};
	if (cache_path[0] == '\0')
	{
		if (__get_path(cache_path, _MAX_BASE_PATH_LEN - 1, _CACHE_DIR, false) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return cache_path;
}

SLPAPI const char *aul_get_app_resource_path(void)
{
	static char resource_path[_MAX_BASE_PATH_LEN] = {0,};
	if (resource_path[0] == '\0')
	{
		if (__get_path(resource_path, _MAX_BASE_PATH_LEN - 1, _RESOURCE_DIR, false) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return resource_path;
}

SLPAPI const char *aul_get_app_shared_data_path(void)
{
	static char shared_data_path[_MAX_BASE_PATH_LEN] = {0,};
	if (shared_data_path[0] == '\0')
	{
		if (__get_path(shared_data_path, _MAX_BASE_PATH_LEN - 1, _SHARED_DATA_DIR, false) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return shared_data_path;
}

SLPAPI const char *aul_get_app_shared_resource_path(void)
{
	static char shared_resource_path[_MAX_BASE_PATH_LEN] = {0,};
	if (shared_resource_path[0] == '\0')
	{
		if (__get_path(shared_resource_path, _MAX_BASE_PATH_LEN - 1, _SHARED_RESOURCE_DIR, false) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return shared_resource_path;
}

SLPAPI const char *aul_get_app_shared_trusted_path(void)
{
	static char shared_trusted_path[_MAX_BASE_PATH_LEN] = {0,};
	if (shared_trusted_path[0] == '\0')
	{
		if (__get_path(shared_trusted_path, _MAX_BASE_PATH_LEN - 1, _SHARED_TRUSTED_DIR, false) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return shared_trusted_path;
}

SLPAPI const char *aul_get_app_external_data_path(void)
{
	static char external_data_path[_MAX_BASE_PATH_LEN] = {0,};
	if (external_data_path[0] == '\0')
	{
		if (__get_path(external_data_path, _MAX_BASE_PATH_LEN - 1, _DATA_DIR, true) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return external_data_path;
}

SLPAPI const char *aul_get_app_external_cache_path(void)
{
	static char external_cache_path[_MAX_BASE_PATH_LEN] = {0,};
	if (external_cache_path[0] == '\0')
	{
		if (__get_path(external_cache_path, _MAX_BASE_PATH_LEN - 1, _CACHE_DIR, true) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return external_cache_path;
}

SLPAPI const char *aul_get_app_external_shared_data_path(void)
{
	static char external_shared_data_path[_MAX_BASE_PATH_LEN] = {0,};
	if (external_shared_data_path[0] == '\0')
	{
		if (__get_path(external_shared_data_path, _MAX_PACKAGE_ID_LEN - 1, _SHARED_DATA_DIR, true) != AUL_R_OK)
		{
			return NULL;
		}
	}
	return external_shared_data_path;
}

SLPAPI const char *aul_get_app_specific_path(void)
{
	return _APP_SPECIFIC_PATH;
}

SLPAPI const char *aul_get_app_external_specific_path(void)
{
	return _EXTERNAL_APP_SPECIFIC_PATH;
}

SLPAPI int aul_get_app_shared_data_path_by_appid(const char *appid, char **path)
{
	return __get_path_by_appid(path, appid, _SHARED_DATA_DIR, false);
}

SLPAPI int aul_get_app_shared_resource_path_by_appid(const char *appid, char **path)
{
	return __get_path_by_appid(path, appid, _SHARED_RESOURCE_DIR, false);
}

SLPAPI int aul_get_app_shared_trusted_path_by_appid(const char *appid, char **path)
{
	return __get_path_by_appid(path, appid, _SHARED_TRUSTED_DIR, false);
}

SLPAPI int aul_get_app_external_shared_data_path_by_appid(const char *appid, char **path)
{
	return __get_path_by_appid(path, appid, _SHARED_DATA_DIR, true);
}

SLPAPI char *aul_get_cmdline_bypid(int pid)
{
	return __proc_get_cmdline_bypid(pid);
}
