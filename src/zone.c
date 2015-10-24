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
#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#include <bundle.h>
#include <vasum.h>

#include "aul.h"
#include "launch.h"
#include "aul_api.h"
#include "aul_svc_db.h"

#define MAX_BUF     1024
#define PID_MAX_DEFAULT 0x8000
#define __ZONE_PREFIX "/var/lib/lxc/%s/rootfs"

extern char *_socket_prefix;
extern char *_root_path;
extern char *_cur_zone;
extern int _pid_offset;
extern char *_svc_db_path;
extern char *_svc_app_info_db_path;

extern void _clear_path_cache(void);

SLPAPI int aul_set_zone(const char *zone, char **old_zone)
{
	if (vsm_is_virtualized())
		return AUL_R_ERROR;

	if (aul_is_initialized()) {
		aul_finalize();
	}

	*old_zone = _cur_zone;
	_clear_path_cache();
	if (zone == NULL) {
		if (_socket_prefix != NULL)
			free(_socket_prefix);
		_socket_prefix = NULL;

		if (_root_path)
			free(_root_path);
		_root_path = NULL;

		if (_svc_db_path != NULL)
			free(_svc_db_path);
		_svc_db_path = NULL;

		if (_svc_app_info_db_path != NULL)
			free(_svc_app_info_db_path);
		_svc_app_info_db_path = NULL;

		_pid_offset = 0;
		_cur_zone = NULL;
		return 0;
	}

	_cur_zone = strdup(zone);
	char path[MAX_BUF] = { '\0', };

	snprintf(path, MAX_BUF - 1, __ZONE_PREFIX"%s",
	         zone, "/tmp/alaunch");
	if (_socket_prefix != NULL)
		free(_socket_prefix);
	_socket_prefix = strdup(path);
	_pid_offset = PID_MAX_DEFAULT;

	snprintf(path, MAX_BUF - 1, __ZONE_PREFIX"/", zone);
	if (_root_path != NULL)
		free(_root_path);
	_root_path = strdup(path);

	snprintf(path, MAX_BUF - 1, __ZONE_PREFIX"/%s", zone, _SVC_DB_PATH);
	if (_svc_db_path != NULL)
		free(_svc_db_path);
	_svc_db_path = strdup(path);

	snprintf(path, MAX_BUF - 1, __ZONE_PREFIX"%s", zone, _SVC_APP_INFO_DB_PATH);
	if (_svc_app_info_db_path != NULL)
		free(_svc_app_info_db_path);
	_svc_app_info_db_path = strdup(path);

	return 0;
}

