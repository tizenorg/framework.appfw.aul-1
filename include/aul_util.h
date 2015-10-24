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


#ifndef __AUL_UTIL_H_
#define __AUL_UTIL_H_

#include <glib.h>
#include "app_launchpad_types.h"

#define SYSTEM_UID	200
#define APP_UID		5000

#define MAX_PACKAGE_STR_SIZE 512
#define MAX_PACKAGE_APP_PATH_SIZE 512
#define MAX_RUNNING_APP_INFO 512

typedef struct _app_status_info_t app_status_info_t;
typedef struct _pkg_status_info_t pkg_status_info_t;

struct _app_status_info_t {
	char *appid;
	char *app_path;
	char *caller;
	char *pkgid;
	char *exec_label;
	int status;
	int pid;
	int pad_pid;
	int last_caller_pid;
	int is_subapp;
	pkg_status_info_t *pkginfo;
	GList *shared_info_list;
};

struct _pkg_status_info_t {
	char *pkgid;
	int status;
	GSList *ui_list;
        GSList *svc_list;
};

struct amdmgr {
	struct appinfomgr *af;  /* appinfo manager */
};

#endif

