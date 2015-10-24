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
#include <glib.h>
#include "aul_dbus.h"
#include <sys/time.h>
#include <stdlib.h>

#define MAX_LOCAL_BUFSZ 128

void request_cb(DBusPendingCall *pc, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	char *str;

	reply = dbus_pending_call_steal_reply(pc);
	dbus_pending_call_unref(pc);

	dbus_error_init(&error);

	if (!dbus_message_get_args(reply, &error,
				   DBUS_TYPE_STRING, &str, DBUS_TYPE_INVALID))
		_E("Failed to complete call");

	printf("filename = %s\n", str);

	dbus_message_unref(reply);

	exit(0);
}

int main(int argc, char **argv)
{
	DBusConnection *bus;
	DBusError error;
	DBusMessage *message;
	DBusPendingCall *pc;
	GMainLoop *loop;
	dbus_bool_t ret;

	char tmp[MAX_LOCAL_BUFSZ];
	char *s;
	struct timeval tv;

	loop = g_main_loop_new(NULL, FALSE);

	dbus_error_init(&error);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (bus == NULL)
		_E("Failed to open bus to bus")

		    dbus_connection_setup_with_g_main(bus, NULL);

	message = dbus_message_new_method_call (
			SERVICE_NAME,PATH_NAME,INTERFACE_NAME,
			METHOD_NAME);

	gettimeofday(&tv, NULL);
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%ld/%ld", tv.tv_sec, tv.tv_usec);
	s = tmp;

	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID);

	ret = dbus_connection_send_with_reply(bus, message, &pc, INT_MAX);
	if (!ret) {
		_E("dbus_connection_send_with_reply() failed.");
		dbus_message_unref(message);
		return -1;
	}
	if (!dbus_pending_call_set_notify(pc, request_cb, NULL, NULL))
		_E("pending call set fail");

	dbus_message_unref(message);

	printf("wait result\n");

	g_main_loop_run(loop);

	return 0;
}

