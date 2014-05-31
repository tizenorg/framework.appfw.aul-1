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

#include <Ecore_X.h>
#include <Ecore_Input.h>
#include <utilX.h>
#include <Ecore.h>
#include <Evas.h>
#include <aul.h>
#include <glib.h>

#include "amd_config.h"
#include "simple_util.h"
#include "app_sock.h"
#include "launch.h"

static struct {
	Evas_Object *win;
	Ecore_Event_Handler *key_up;
	Ecore_Event_Handler *key_down;
} key_info = {
	.win = NULL,
	.key_up = NULL,
	.key_down = NULL,
};

GSList *key_pid_list = NULL;

static Eina_Bool __key_release_cb(void *data, int type, void *event);
static Eina_Bool __key_press_cb(void *data, int type, void *event);

static Eina_Bool __key_release_cb(void *data, int type, void *event)
{
	Evas_Event_Key_Up *ev = event;
	int ret;
	GSList *entry;
	int *pid_data;
	bundle *kb;

	_D("Released");

	if (!ev) {
		_D("Invalid event object");
		return ECORE_CALLBACK_RENEW;
	}

	entry = key_pid_list;
	if (entry && entry->data) {
		pid_data = (int *) entry->data;

		kb = bundle_create();
		bundle_add(kb, AUL_K_MULTI_KEY, ev->keyname);
		bundle_add(kb, AUL_K_MULTI_KEY_EVENT, AUL_V_KEY_RELEASED);

		ret = app_send_cmd(*pid_data, APP_KEY_EVENT, kb);
		if (ret < 0)
			_E("app_send_cmd failed with error %d\n", ret);

		bundle_free(kb);
	}

	return ECORE_CALLBACK_RENEW;
}


static Eina_Bool __key_press_cb(void *data, int type, void *event)
{
	Evas_Event_Key_Down *ev = event;
	int ret;
	GSList *entry;
	int *pid_data;
	bundle *kb;

	_D("Pressed");

	if (!ev) {
		_D("Invalid event object");
		return ECORE_CALLBACK_RENEW;
	}

	entry = key_pid_list;
	if (entry && entry->data) {
		pid_data = (int *) entry->data;

		kb = bundle_create();
		bundle_add(kb, AUL_K_MULTI_KEY, ev->keyname);
		bundle_add(kb, AUL_K_MULTI_KEY_EVENT, AUL_V_KEY_PRESSED);

		ret = app_send_cmd(*pid_data, APP_KEY_EVENT, kb);
		if (ret < 0)
			_E("app_send_cmd failed with error %d\n", ret);

		bundle_free(kb);
	}

	return ECORE_CALLBACK_RENEW;
}

int _register_key_event(int pid)
{
	int *pid_data;
	GSList *entry;

	pid_data = malloc(sizeof(int));
	*pid_data = pid;

	key_pid_list = g_slist_prepend(key_pid_list, pid_data);

	_D("===key stack===");

	for (entry = key_pid_list; entry; entry = entry->next) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			_D("pid : %d",*pid_data);
		}
	}

	return 0;
}

int _unregister_key_event(int pid)
{
	GSList *entry;
	int *pid_data;

	for (entry = key_pid_list; entry;) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			entry = entry->next;
			if(pid == *pid_data) {
				key_pid_list = g_slist_remove(key_pid_list, pid_data);
				free(pid_data);
			}
		}
	}

	_D("===key stack===");

	for (entry = key_pid_list; entry; entry = entry->next) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			_D("pid : %d",*pid_data);
		}
	}

	return 0;
}

int _key_init()
{
	key_info.win = ecore_x_window_input_new(0, 0, 0, 1, 1);
	if (!key_info.win) {
		_D("Failed to create hidden window");
	}

	ecore_x_icccm_title_set(key_info.win, "acdaemon,key,receiver");
	ecore_x_netwm_name_set(key_info.win, "acdaemon,key,receiver");
	ecore_x_netwm_pid_set(key_info.win, getpid());

	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_PLAYCD, SHARED_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_STOPCD, SHARED_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_PAUSECD, SHARED_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_NEXTSONG, SHARED_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_PREVIOUSSONG, SHARED_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_REWIND, SHARED_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_FASTFORWARD, SHARED_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_PLAYPAUSE, SHARED_GRAB);

	key_info.key_up = ecore_event_handler_add(ECORE_EVENT_KEY_UP, __key_release_cb, NULL);
	if (!key_info.key_up) {
		_D("Failed to register a key up event handler");
	}

	key_info.key_down = ecore_event_handler_add(ECORE_EVENT_KEY_DOWN, __key_press_cb, NULL);
	if (!key_info.key_down) {
		_D("Failed to register a key down event handler");
	}

	return 0;
}

