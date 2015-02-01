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


#ifndef __APP_SIGNAL_H__
#define __APP_SIGNAL_H__

#include <dbus/dbus.h>

#define AUL_DBUS_PATH "/aul/dbus_handler"
#define AUL_DBUS_SIGNAL_INTERFACE "com.samsung.aul.signal"
#define AUL_DBUS_APPDEAD_SIGNAL	"app_dead"
#define AUL_DBUS_APPLAUNCH_SIGNAL	"app_launch"
#define AUL_DBUS_HOMELAUNCH_SIGNAL	"home_launch"

#ifdef _APPFW_FEATURE_CPU_BOOST
#define SYSTEM_BUS_NAME       "org.tizen.system.deviced"
#define SYSTEM_OBJECT_PATH    "/Org/Tizen/System/DeviceD/PmQos"
#define SYSTEM_INTERFACE_NAME "org.tizen.system.deviced.PmQos"
#define SYSTEM_METHOD_NAME    "AppLaunch"
#endif

#define SYSTEM_PATH_CORE    	"/Org/Tizen/System/DeviceD/Core"
#define SYSTEM_INTERFACE_CORE 	"org.tizen.system.deviced.core"

#define SYSTEM_SIGNAL_BOOTING_DONE		"BootingDone"

#define SYSTEM_PATH_SYSNOTI    	"/Org/Tizen/System/DeviceD/SysNoti"
#define SYSTEM_INTERFACE_SYSNOTI 	"org.tizen.system.deviced.SysNoti"

#define SYSTEM_SIGNAL_COOLDOWN_CHANGED		"CoolDownChanged"

#define RESOURCED_PATH_CORE    	"/Org/Tizen/ResourceD/Process"
#define RESOURCED_INTERFACE_CORE 	"org.tizen.resourced.process"

#define RESOURCED_SIGNAL_PROCESS_STATUS		"ProcStatus"

#define ROTATION_BUS_NAME       "org.tizen.system.coord"
#define ROTATION_OBJECT_PATH    "/Org/Tizen/System/Coord/Rotation"
#define ROTATION_INTERFACE_NAME "org.tizen.system.coord.rotation"
#define ROTATION_METHOD_NAME    "Degree"

#define RESOURCED_PROC_OBJECT		"/Org/Tizen/ResourceD/Process"
#define RESOURCED_PROC_INTERFACE	"org.tizen.resourced.process"
#define RESOURCED_PROC_METHOD		"ProcExclude"

#define RESOURCED_PROC_WATCHDOG_SIGNAL "ProcWatchdog"

#define PROC_TYPE_EXCLUDE		"exclude"
#define PROC_TYPE_INCLUDE		"include"
#define PROC_TYPE_WAKEUP		"wakeup"

#ifdef _APPFW_FEATURE_VISIBILITY_CHECK_BY_LCD_STATUS
#define DEVICED_PATH_DISPLAY	"/Org/Tizen/System/DeviceD/Display"
#define DEVICED_INTERFACE_DISPLAY	"org.tizen.system.deviced.display"

#define DEVICED_SIGNAL_LCD_ON			"LCDOn"
#define DEVICED_SIGNAL_LCD_OFF		"LCDOff"
#endif
#endif
