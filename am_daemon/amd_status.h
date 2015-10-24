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

#ifndef __AUL_AMD_STATUS_H_
#define __AUL_AMD_STATUS_H_

#include <glib.h>

int _status_add_app_info_list(const char *appid, const char *app_path,
	const char *caller, int pid, int pad_pid, int is_subapp);
int _status_update_app_info_list(int pid, int status, gboolean force);
int _status_update_app_info_caller_pid(int pid, int caller_pid);
int _status_get_app_info_last_caller_pid(int pid);
int _status_remove_app_info_list(int pid);
int _status_get_app_info_status(int pid);
int _status_app_is_running(const char *appid);
void _status_find_service_apps(int pid, enum app_status, void (*send_event_to_svc_core) (int));
void _status_check_service_only(int pid, void (*send_event_to_svc_core) (int));
char* _status_app_get_appid_bypid(int pid);

int _status_send_running_appinfo(int fd);
int _status_app_is_running_v2(const char *appid);
int _status_app_is_running_v2_cached(const char *appid);
int _status_app_is_running_from_cache(const char *appid);
int _status_send_running_appinfo_v2(int fd);
int _status_get_pkgname_bypid(int pid, char *pkgname, int len);
int _status_get_appid_bypid(int fd, int pid);
int _status_get_pkgid_bypid(int fd, int pid);
int _status_get_cmdline(int fd, int pid);
int _status_send_group_info(int fd);
char* _status_get_caller_by_appid(const char *appid);
int _status_get_cooldown_status(void);
int _status_set_exec_label(int pid, const char *exec_label);
const char* _status_get_exec_label(int pid);
int _status_set_caller_exec_label(int pid, const char *exec_label);
int _status_add_shared_info(int pid, const char *exec_label, char **paths);
int _status_clear_shared_info_list(int pid);
GList* _status_get_shared_info_list(int pid);

gboolean _status_check_window_ready(void);

#ifdef _APPFW_FEATURE_AMD_MODULE_LOG
int _status_log_save(const char *tag, const char *message);
int _status_log_write(void);
#endif

//TODO : remove

typedef struct _item_pkt_t {
	int pid;
	char appid[512];
} item_pkt_t;

#ifdef _APPFW_FEATURE_BG_PROCESS_LIMIT
gboolean __add_item_running_list(gpointer user_data);
#endif

enum cooldown_status_val {
	COOLDOWN_RELEASE,
	COOLDOWN_WARNING,
	COOLDOWN_LIMIT,
};

typedef struct _shared_info_t {
	char *owner_exec_label;
	char **paths;
} shared_info_t;

#endif

