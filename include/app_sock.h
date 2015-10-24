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


#ifndef __APP_PKT_H_
#define __APP_PKT_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <sys/socket.h>
#include <linux/un.h>
#include "aul_zone.h"

#include "app_launchpad_types.h"

enum app_cmd {
	APP_START,
	APP_OPEN,
	APP_RESUME,
	APP_RESUME_BY_PID,
	APP_TERM_BY_PID,
	APP_TERM_BY_PID_WITHOUT_RESTART,
	APP_RESULT,
	APP_START_RES,
	APP_CANCEL,
	APP_KILL_BY_PID,
	APP_ADD_HISTORY,
	APP_RUNNING_INFO,
	APP_RUNNING_INFO_MEMORY,
	APP_RUNNING_INFO_RESULT,
	APP_IS_RUNNING,
	APP_GET_APPID_BYPID,
	APP_GET_PKGID_BYPID,
	APP_GET_INFO_OK,
	APP_GET_INFO_ERROR,
	APP_KEY_EVENT,
	APP_KEY_RESERVE,
	APP_KEY_RELEASE,
	APP_STATUS_UPDATE,
	APP_RUNNING_LIST_UPDATE,
	APP_TERM_REQ_BY_PID,
	APP_START_ASYNC,
	APP_TERM_BY_PID_ASYNC,
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	APP_START_MULTI_INSTANCE,
#endif
	APP_GROUP_GET_WINDOW,
	APP_GROUP_GET_LEADER_PIDS,
	APP_GROUP_GET_GROUP_PIDS,
	APP_GROUP_CLEAR_TOP,
	APP_GROUP_GET_LEADER_PID,
	APP_GROUP_GET_FG,
	APP_GROUP_SET_WINDOW,
	APP_GROUP_LOWER,
	APP_GROUP_GET_IDLE_PIDS,
	APP_GET_CMDLINE,
	APP_TERM_BGAPP_BY_PID,
	APP_PAUSE,
	APP_PAUSE_BY_PID,
	APP_GET_PID,
	APP_GET_PID_CACHE,
	APP_GET_STATUS,
	APP_SET_PROCESS_GROUP,
	APP_GET_GROUP_INFO,
	APP_SUSPEND,
	APP_WAKE,
	APP_GET_LAST_CALLER_PID,
};

#define AUL_SOCK_PREFIX _get_sock_prefix()
#define AUL_SOCK_MAXBUFF 131071
#define ELOCALLAUNCH_ID 128
#define EILLEGALACCESS 127
#define ETERMINATING 126
#define ENOLAUNCHPAD 125
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
#define EUGLOCAL_LAUNCH 124
#endif
#define EREJECTED 123
#define ENOAPP 122



typedef struct _app_pkt_t {
	int cmd;
	int len;
	unsigned char data[1];
} app_pkt_t;

int __create_server_sock(int pid);
int __create_client_sock(int pid);
int __app_send_raw(int pid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_noreply(int pid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_delay_reply(int pid, int cmd, unsigned char *kb_data, int datalen);
app_pkt_t *__app_recv_raw(int fd, int *clifd, struct ucred *cr);
app_pkt_t *__app_send_cmd_with_result(int pid, int cmd, unsigned char *kb_data, int datalen);

#endif

