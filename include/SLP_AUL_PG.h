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


/**

 *
 * @ingroup   SLP_PG
 * @defgroup   AUL Application Utility Library


@par AUL Programming Guide

<h1 class="pg"> Introduction</h1>
<h2 class="pg"> Purpose of this document</h2>
The purpose of this document is to describe how applications can use Application Utility Library APIs.\n
This document gives only programming guidelines to application engineers.

<h2 class="pg"> Scope</h2>
The scope of this document is limited to Samsung platform Application Utility Library API usage.
@}

@defgroup AUL_Architecture 1.Architecture
@ingroup AUL
@{
<h1 class="pg">Application Utility Library Architecture</h1>
<h2 class="pg"> Architecture overview</h2>
Application Utility Library (AUL) is responsible for launching / resuming / terminating application. It support low-level API for it. AUL also support high-level API to launch default applications based on MIME types and URI(based on regular expression). It also provides the information of applications that are running.\n

In single instance model, if a currently running application is requested to be launched again, the AUL sends the reset event to the application. \n

Low-level AUL API(primitive APIs) expects the application to provide APN(application package name) it wishes to launch.\n Low-level interface used by AUL are as shown below. Unix Domain Socket is used to send events between launchpad deamon and applications.
Launchpad deamon is responsible for setup default configuration of application like "setup authority", " setup application scale",...  DB is used to store / retain default configuration of application.

@image html low-level2.png "Low-level AUL diagram"

High-level APIs support to launch based on MIME types(based on filename, URI, service name). This feature is abstraction of APN. Most develpers want to launch based on filename, URI, service name without knowing APN. Below is example list.
 - When developer open browser appliction with "http://www.samsung.com".
 - When developer open application with filename "/usr/share/myimage.png"
 - When developer launching application with service name "camera" and service command "take_picture"

Internally, AUL finds MIME type with given filename, URI, service name. Next, AUL find APN of default application from DB with associated MIME type. and then, AUL launch the application using primitive AUL APIs.

@image html high-level2.png "High-Level AUL diagram"
@}

@defgroup AUL_Feature 2.Feature
@ingroup AUL
@{
<h2 class="pg">Application Utility Library Features</h2>
Application Utility Library has the following features:\n

 - Launch/Resume/Terminate Application (Primitive APIs)
	- It can launch an application that is not currently running.
	- It sends reset/resume/terminate event if application is already running

 - Application List or information
	- It provides the list of applications that are running.
	- It provides information of running applications

 - MIME support (High-Level APIs)
	- AUL can get MIME type associated with the file and content
	- AUL can get the default application associated with the MIME type.
	- AUL can launch default applications associated with the MIME(file or content) when AUL find default application.
	- AUL automatically launch "application selection popup" when AUL don't find default application associated with the MIME(file or content)

 - Application Service support (High-Level APIs)
	- AUL can launch applications based on service name and service command
@}

@defgroup AUL_Use_Cases1 Launch/Resume/Terminate an Application
@ingroup AUL_Use_Cases
@{
<h1 class="pg"> AUL features with sample code</h1>

<h2 class="pg"> Launch/Resume/Terminate an application</h2>

Caller application
- LAUNCH or RESET request without return callback function
- The first parameter(pkg_name) has to be registered through .desktop file.
- The second parameter(bundle) give dictionary style's arguments to launched(callee) application.

@code
// the package name of this app is a "org.tizen.caller"
#include <aul.h>
#include <bundle.h>
void launch_func()
{
	bundle* kb;
	kb = bundle_create();
	bundle_add(kb, "key1", "val1");
	bundle_add(kb, "key2", "val2");
	bundle_add(kb, "key3", "val3");
	aul_launch_app("org.tizen.callee",kb);
	bundle_free(kb);
}
@endcode

- Return the application to the foreground
- You might want to use aul_open_app when you need to resume,
	e.g., get it back to foreground, an application
- If the application is not running, the application will be launched.

@code
// the package name of this app is a "org.tizen.caller"
#include <aul.h>
void resume_func()
{
	aul_open_app("org.tizen.callee");
}
@endcode


Callee application

- Integated with Appcore
- If you use Appcore Library, Aul library already was integrated.\n
  You must implementation Appcore RESET , RESUME, TERMINATE handler.\n
  This is example code. This is NOT guidance \n
- If you want more information,SEE for AppCore document.

@code
//Callee application with AppCore

#include <aul.h>
#include <appcore-efl.h>
#include <bundle.h>
          :

static int app_create(void *data)
{
	// initialize your app without argument
	return 0;
}

static void _app_initialize_with_arg(bundle *b)
{
	// initialize your app with argument
}

//
// called by window manager event
// or called by aul_open_app
// create your resume handler
//
static int app_resume(void *data){return 0;}
static int app_pause(void *data) {return 0;}

//
// called by aul_terminate_api
//
static int app_terminate(void *data){return 0;}

//
// called by aul_launch_app or aul_launch_api_with_result
// this is example code. create your reset handler
//
static int app_reset(bundle *b, void *data)
{
	char* mime_type;
	if(bundle_get_val(ad->kb, AUL_K_ARGV0))   // when launch
		_app_initialize_with_arg(b);
	else{                                        // when receiving reset event
		mime_type = bundle_get_val(b, AUL_K_MIME_TYPE);
		if (!mime_type){
			elm_win_activate(..);
			return 0;
		}else{
			update_list(mime_type);
		}
	}
}

int main(int argc, char *argv[])
{
	struct appcore_ops ops = {
		.create = app_create,
		.terminate = app_terminate,
		.pause = app_pause,
		.resume = app_resume,
		.reset = app_reset,
	};

	return appcore_efl_main(PACKAGE, &argc, &argv, &ops);
}
@endcode


- SET with AUL native handler
- In special case, if you don't use Appcore library, this is aul callee's example

@code
// Callee application
#include <aul.h>
#include <bundle.h>
#include <Ecore.h>

static int aul_handler(aul_type type, bundle *kb,void* data)
{
	char* val1, *val2
	switch(type){
		case AUL_START:
			// same to Appcore RESET callback
			val1 = bundle_get_val(kb, "phone_number");
			val2 = bundle_get_val(kb, "store");
			break;
		case AUL_RESUME:
			// same to Appcore RESUME callback
			break;
		case AUL_TERMINATE:
			// same to Appcore TERMINATE callback
			break;
	}
	return 0;
}

int main(int argc, char** argv)
{
	ecore_init();

	aul_launch_init(aul_handler,NULL);
	// enable this if you want to handle at aul_handler when launch
	aul_launch_argv_handler(argc, argv);

	ecore_main_loop_begin();  // You must need ecore or glib mainloop
	return 0;
}
@endcode
@}

@defgroup AUL_Use_Cases2 Get Running Application State
@ingroup AUL_Use_Cases
@{
<h2 class="pg"> Get Running Application State </h2>

- Getting running application list
- This AUL function is used to get the list of all the applications that are currently running.

@code
#include <aul.h>

int iterfunc(const aul_app_info* info, void* data)
{
	printf("package name: %s\n", info->pkg_name);
	printf("running pid: %d\n", info->pid);
	printf("application executable path: %s\n", info->app_path);
	return 0;
}

int main (int argc, char **argv)
{
	aul_app_get_running_app_info(iterfunc,NULL);
}
@endcode

- Get application running state
- This AUL function is used to get application's state

@code
#include <aul.h>

int main (int argc, char **argv)
{
	if(aul_app_is_running("org.tizen.app2"))
		printf("application is running");
}
@endcode

- Dead Handler (Set dead handler)
- aul_listen_app_dead_signal track killed application.
  For example, 3rd party application can register indicator icon at indicator service. When 3rd party application abnormally terminated after set icon at indicator, indicator service should collect garbage icon set by the application.

@code
#include <aul.h>

int dead_tracker(int pid, void* data)
{
	printf("the application with %d pid was killed",pid);
	return 0;
}

void set_dead_handler_func()
{
	aul_listen_app_dead_signal(dead_tracker,NULL);
}
@endcode
@}

@defgroup AUL_Use_Cases3 Launch Based on Service Name and Command
@ingroup AUL_Use_Cases
@{
<h2 class="pg"> High Level APIs - launch based on service name and command </h2>

- This AUL functions is used to launch default application based on service name and service command. In addition,AUL package support to set/get default application(package name) associated with service name and service command. This APIs also support to receive result from launched(requested) application.

- Launch default application associated with service name and service command.
- You can use aul_open_service when you launch an application associated with service name and service command
- If the service support to receive result, you can add result callback function.
- the API is asynchronous.(non-blocking API)

@code
// the package name of this app is a "org.tizen.caller"
#include <aul.h>
#include <bundle.h>
void cb_func( bundle* kb, int reserved, void* data)
{
	char *id;
	id = bundle_get_val(kb, "searched_id");
	printf("searched id %s", id);
}

void service_launch_func()
{
	void* user_data;
	bundle* kb;

	user_data = (void*)strdup("my_priv_data");
	kb = bundle_create();
	bundle_add(kb, "storage_type", "SIM");
	aul_open_appsvc("contact", "search", kb, cb_func, user_data);
	bundle_free(kb);
}
@endcode

- This is sample code to send result to caller in application(callee) given the service.
- aul_send_service_result send result msg based on received bundle.

@code
// Callee application
// the package name of this app is a "org.tizen.callee"

#include <aul.h>
#include <bundle.h>

void send_result(bundle *recved_bundle, char* id)
{
	bundle* res_kb;
	aul_create_result_bundle(recved_bundle,&res_kb);
	bundle_add(res_kb, "searched_id", id);
	aul_send_service_result(res_kb);
	bundle_free(res_kb);
}
@endcode
@}

*/

/**
@addtogroup AUL
@{
	@defgroup AUL_Use_Cases Use Cases
@}
*/


