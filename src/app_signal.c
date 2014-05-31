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


#include <stdio.h>
#include "app_signal.h"
#include "aul_api.h"
#include "simple_util.h"
#include "aul.h"

static int (*_app_dead_handler) (int pid, void *data);
static void *_app_dead_data;

static int (*_app_launch_handler) (int pid, void *data);
static void *_app_launch_data;

static int (*_booting_done_handler) (int pid, void *data);
static void *_booting_done_data;

static DBusConnection *bus;
static int app_dbus_signal_handler_initialized = 0;

static DBusHandlerResult
__app_dbus_signal_filter(DBusConnection *conn, DBusMessage *message,
		       void *user_data)
{
	const char *sender;
	const char *interface;
	int pid;

	DBusError error;
	dbus_error_init(&error);

	sender = dbus_message_get_sender(message);
	if (sender == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_bus_get_unix_user(conn, sender, &error) != 0) {
		_E("reject by security issue - no allowed sender\n");
		dbus_error_free(&error);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	interface = dbus_message_get_interface(message);
	if (interface == NULL) {
		_E("reject by security issue - no interface\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (dbus_message_is_signal(
	  message, interface, AUL_DBUS_APPDEAD_SIGNAL)) {
		if (dbus_message_get_args(message, &error, DBUS_TYPE_UINT32,
		     &pid, DBUS_TYPE_INVALID) == FALSE) {
			_E("Failed to get data: %s", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		if (_app_dead_handler)
			_app_dead_handler(pid, _app_dead_data);
	} else if (dbus_message_is_signal(
	  message, interface, AUL_DBUS_APPLAUNCH_SIGNAL)) {
		if (dbus_message_get_args(message, &error, DBUS_TYPE_UINT32,
		     &pid, DBUS_TYPE_INVALID) == FALSE) {
			_E("Failed to get data: %s", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		if (_app_launch_handler)
			_app_launch_handler(pid, _app_launch_data);
	} else if (dbus_message_is_signal(
	  message, interface, SYSTEM_SIGNAL_BOOTING_DONE)) {
		if (_booting_done_handler)
			_booting_done_handler(pid, _booting_done_data);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

int __app_dbus_signal_handler_init(void)
{
	int ret = 0;

	if (app_dbus_signal_handler_initialized)
		return 0;

	ret = __app_dbus_signal_handler_init_with_param(AUL_DBUS_PATH, AUL_DBUS_SIGNAL_INTERFACE);

	app_dbus_signal_handler_initialized = 1;

	return ret;
}

int __app_dbus_signal_handler_init_with_param(const char* path, const char* interface)
{
	DBusError error;
	char rule[MAX_LOCAL_BUFSZ];

	dbus_error_init(&error);
	bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
	if (!bus) {
		_E("Failed to connect to the D-BUS daemon: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}
	dbus_connection_setup_with_g_main(bus, NULL);

	snprintf(rule, MAX_LOCAL_BUFSZ,
		 "path='%s',type='signal',interface='%s'", path, interface);
	/* listening to messages */
	dbus_bus_add_match(bus, rule, &error);
	if (dbus_error_is_set(&error)) {
		_E("Fail to rule set: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}

	if (dbus_connection_add_filter(bus, 
		__app_dbus_signal_filter, NULL, NULL) == FALSE)
		return -1;

	_D("app signal initialized");

	return 0;
}

int __app_dbus_signal_handler_fini(void)
{
	int ret = 0;

	if (!app_dbus_signal_handler_initialized)
		return 0;

	ret = __app_dbus_signal_handler_fini_with_param(AUL_DBUS_PATH, AUL_DBUS_SIGNAL_INTERFACE);

	app_dbus_signal_handler_initialized = 0;

	return ret;
}

int __app_dbus_signal_handler_fini_with_param(const char* path, const char* interface)
{
	DBusError error;
	char rule[MAX_LOCAL_BUFSZ];


	dbus_error_init(&error);

	dbus_connection_remove_filter(bus, __app_dbus_signal_filter, NULL);

	snprintf(rule, MAX_LOCAL_BUFSZ,
		 "path='%s',type='signal',interface='%s'", path, interface);
	dbus_bus_remove_match(bus, rule, &error);
	if (dbus_error_is_set(&error)) {
		_E("Fail to rule unset: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}

	dbus_connection_close(bus);
	dbus_connection_unref(bus);

	_D("app signal finialized");

	return 0;
}

SLPAPI int aul_listen_app_dead_signal(int (*func) (int, void *), void *data)
{
	if (func) {
		if (__app_dbus_signal_handler_init() < 0) {
			_E("error app signal init");
			return AUL_R_ERROR;
		}
	} else if (_app_launch_handler == NULL) {
		if (__app_dbus_signal_handler_fini() < 0) {
			_E("error app signal fini");
			return AUL_R_ERROR;
		}
	}
	_app_dead_handler = func;
	_app_dead_data = data;

	return AUL_R_OK;
}

SLPAPI int aul_listen_app_launch_signal(int (*func) (int, void *), void *data)
{
	if (func) {
		if (__app_dbus_signal_handler_init() < 0) {
			_E("error app signal init");
			return AUL_R_ERROR;
		}
	} else if (_app_dead_handler == NULL) {
		if (__app_dbus_signal_handler_fini() < 0) {
			_E("error app signal fini");
			return AUL_R_ERROR;
		}
	}
	_app_launch_handler = func;
	_app_launch_data = data;

	return AUL_R_OK;
}

SLPAPI int aul_listen_booting_done_signal(int (*func) (int, void *), void *data)
{
	if (func) {
		if (__app_dbus_signal_handler_init_with_param(SYSTEM_PATH_CORE, SYSTEM_INTERFACE_CORE) < 0) {
			_E("error app signal init");
			return AUL_R_ERROR;
		}
	} else if (_booting_done_handler == NULL) {
		if (__app_dbus_signal_handler_fini_with_param(SYSTEM_PATH_CORE, SYSTEM_INTERFACE_CORE) < 0) {
			_E("error app signal fini");
			return AUL_R_ERROR;
		}
	}
	_booting_done_handler = func;
	_booting_done_data = data;

	return AUL_R_OK;

}

