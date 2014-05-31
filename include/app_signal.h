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


#ifndef __APP_DBUS_H__
#define __APP_DBUS_H__

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#define AUL_DBUS_PATH "/aul/dbus_handler"
#ifdef WEARABLE_PROFILE
#define AUL_DBUS_SIGNAL_INTERFACE "com.samsung.aul.signal"
#else
#define AUL_DBUS_SIGNAL_INTERFACE "org.tizen.aul.signal"
#endif
#define AUL_DBUS_APPDEAD_SIGNAL	"app_dead"
#define AUL_DBUS_APPLAUNCH_SIGNAL	"app_launch"
#define AUL_DBUS_HOMELAUNCH_SIGNAL	"home_launch"

#define SYSTEM_BUS_NAME       "org.tizen.system.deviced"

#define SYSTEM_OBJECT_PATH    "/Org/Tizen/System/DeviceD/PmQos"
#define SYSTEM_INTERFACE_NAME "org.tizen.system.deviced.PmQos"
#define SYSTEM_METHOD_NAME    "AppLaunch"

#define SYSTEM_PATH_CORE    	"/Org/Tizen/System/DeviceD/Core"
#define SYSTEM_INTERFACE_CORE 	"org.tizen.system.deviced.core"

#define SYSTEM_SIGNAL_BOOTING_DONE		"BootingDone"

#endif
