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



int _status_add_app_info_list(char *appid, char *app_path,const char *caller, int pid, int pad_pid);
int _status_update_app_info_list(int pid, int status);
int _status_remove_app_info_list(int pid);
int _status_get_app_info_status(int pid);
int _status_app_is_running(char *appid);
int _status_send_running_appinfo(int fd);
int _status_app_is_running_v2(char *appid);
int _status_send_running_appinfo_v2(int fd);
int _status_get_pkgname_bypid(int pid, char *pkgname, int len);
int _status_get_appid_bypid(int fd, int pid);
int _status_get_pkgid_bypid(int fd, int pid);
char* _status_get_caller_by_appid(const char *appid);
int _status_get_cooldown_status(void);



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

