/*
Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved 
PROPRIETARY/CONFIDENTIAL
This software is the confidential and proprietary information of 
SAMSUNG ELECTRONICS ("Confidential Information"). You agree and acknowledge that 
this software is owned by Samsung and you 
shall not disclose such Confidential Information and shall 
use it only in accordance with the terms of the license agreement 
you entered into with SAMSUNG ELECTRONICS.  SAMSUNG make no 
representations or warranties about the suitability 
of the software, either express or implied, including but not 
limited to the implied warranties of merchantability, fitness for 
a particular purpose, or non-infringement. 
SAMSUNG shall not be liable for any damages suffered by licensee arising out of or 
related to this software.
*/

#include <stdio.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#define _E(fmt, arg...)\
	do {\
		printf(fmt " : %s\n", ##arg, error.message);\
		dbus_error_free(&error);\
		exit(1);\
	} while (0);

#define SERVICE_NAME "org.tizen.camera"
#define PATH_NAME "/org/tizen/camera"
#define INTERFACE_NAME SERVICE_NAME".app_result"
#define METHOD_NAME "take_and_get"
