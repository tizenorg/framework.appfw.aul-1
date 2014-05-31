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
#include <glib.h>
#include <aul.h>
#include "aul_util.h"
#include "simple_util.h"

GSList *app_status_info_list = NULL;

int _add_app_status_info_list(char *appid, int pid)
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
	info_t->status = STATUS_LAUNCHING;
	info_t->pid = pid;
	app_status_info_list = g_slist_append(app_status_info_list, info_t);

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		_D("%s, %d, %d", info_t->appid, info_t->pid, info_t->status);
	}

	return 0;
}

int _update_app_status_info_list(int pid, int status)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid) {
			info_t->status = status;
			break;
		}
	}

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		_D("%s, %d, %d", info_t->appid, info_t->pid, info_t->status);
	}

	return 0;
}

int _remove_app_status_info_list(int pid)
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

		_D("%s, %d, %d", info_t->appid, info_t->pid, info_t->status);
	}

	return 0;
}

