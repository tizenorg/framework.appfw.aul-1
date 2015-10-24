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


#ifndef __AUL_H__
#define __AUL_H__

#include <errno.h>
#include <bundle.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @mainpage
 *
 * This is new version of Application Utility Library
 *
 * Almost function's input param is application package name(APN).\n
 * APN is application package name which is set by developer.\n
 * In case of in-house application, prefix is org.tizen.\n
 * It is different from debian package name.\n
 *
 * - Debian Package Name : Name which is managed by package manager
 * - Application Package Name : Name which is used by AUL
 * - Execution Path : real program executable path
 */

/**
 * @open
 * @ingroup APPLICATION_FRAMEWORK
 * @defgroup aul  Application Utility Library
 * @{
 */


/**
 * @file 	aul.h
 * @brief 	Application Utility Library header
 *
 * Patched by    Knhoon Baik <knhoon.baik@samsung.com>
 * Patched by    Youmin Ha   <youmin.ha@samsung.com>
 */

/**
 * @addtogroup aul
 * @{
 */

/**
 * @brief Return values in AUL.
 */
typedef enum _aul_return_val {
	AUL_R_EREJECTED = -14, 	/**< App disable for mode*/
	AUL_R_ENOAPP = -13,		/**< Failed to find app ID or pkg ID */
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	AUL_R_UG_LOCAL = -12,
#endif
	AUL_R_EHIDDENFORGUEST = -11,    /**< App hidden for guest mode */
	AUL_R_ENOLAUNCHPAD = -10,	/**< no launchpad */
	AUL_R_ETERMINATING = -9,	/**< application terminating */
	AUL_R_EILLACC = -8,		/**< Illegal Access */
	AUL_R_LOCAL = -7,		/**< Launch by himself */
	AUL_R_ETIMEOUT = -6,		/**< Timeout */
	AUL_R_ECANCELED = -5,		/**< Operation canceled */
	AUL_R_EINVAL = -4,		/**< Invalid argument */
	AUL_R_ECOMM = -3,		/**< Comunication Error */
	AUL_R_ENOINIT = -2,		/**< AUL handler NOT initialized */
	AUL_R_ERROR = -1,		/**< General error */
	AUL_R_OK = 0			/**< General success */
}aul_return_val;

enum app_status {
	STATUS_LAUNCHING,
	STATUS_CREATED,
	STATUS_FOCUS,
	STATUS_VISIBLE,
	STATUS_BG,
	STATUS_DYING,
	STATUS_HOME,
	STATUS_NORESTART,
	STATUS_SERVICE
};

/** @} */

/**
 * @defgroup aul_launch		Primitive APIs to launch/resume/terminate application
 * @ingroup aul
 * @brief
 *	APIs to launch/resume/terminate application
 *	- Launch application based on application package name
 *	- Resume application based on application package name
 *	- Resume application based on pid (required root or inhouse permisssion)
 *	- Terminate application base on pid (required root or inhouse permission)
 *
 *	AUL internal information
 *	- AUL grant pid, gid to launched application for security
 *	- AUL send RESET/RESUME/TERM event for running application in case of single instance
 *	- AUL set application enviroment based on desktop entry
 *	- AUL support single instance / multi instance
 *	- AUL support application data exchange format (bundle)
 */

/**
 * @addtogroup aul_launch
 * @{
 */

typedef enum _aul_type{
	AUL_START,
	AUL_RESUME,
	AUL_TERMINATE,
	AUL_TERMINATE_BGAPP,
	AUL_PAUSE,
	AUL_SUSPEND,
	AUL_WAKE,
}aul_type;

/** AUL internal private key */
#define AUL_K_PKG_NAME		"__AUL_PKG_NAME__"
/** AUL internal private key */
#define AUL_K_WAIT_RESULT	"__AUL_WAIT_RESULT__"
/** AUL internal private key */
#define AUL_K_SEND_RESULT	"__AUL_SEND_RESULT__"
/** AUL internal private key */
#define AUL_K_TASK_MANAGE	"__AUL_TASK_MANAGE__"
/** AUL internal private key */
#define AUL_K_APP_TYPE		"__AUL_APP_TYPE__"
/** AUL internal private key - To check original caller's identity */
#define AUL_K_ORG_CALLER_PID	"__AUL_ORG_CALLER_PID__"
/** AUL internal private key - To check forwarded callee app's pid */
#define AUL_K_FWD_CALLEE_PID	"__AUL_FWD_CALLEE_PID__"

/** AUL internal private key */
#define AUL_K_NO_CANCEL        "__AUL_NO_CANCEL__"

/** AUL public key - To check caller's secuirty */
#define AUL_K_CALLER_PID	"__AUL_CALLER_PID__"
/** AUL public key - To check callee's secuirty */
#define AUL_K_CALLEE_PID	"__AUL_CALLEE_PID__"

/** AUL public key - To check caller's secuirty */
#define AUL_K_CALLER_APPID	"__AUL_CALLER_APPID__"
/** AUL public key - To check caller's secuirty */
#define AUL_K_CALLEE_APPID	"__AUL_CALLEE_APPID__"

/** AUL public key - To find argv0 */
#define AUL_K_ARGV0		"__AUL_ARGV0__"
/** AUL public key - To measure launching time */
#define AUL_K_STARTTIME		"__AUL_STARTTIME__"

/** AUL public key - To support launching based on mime type */
#define AUL_K_MIME_TYPE		"__AUL_MIME_TYPE__"
/** AUL public key - To support launching based on mime type */
#define AUL_K_UNALIASED_MIME_TYPE		"__AUL_UNALIASED_MIME_TYPE__"
/** AUL public key - To support launching based on mime type */
#define AUL_K_MIME_CONTENT	"__AUL_MIME_CONTENT__"

/** AUL public key - To support launching based on service */
#define AUL_K_SERVICE_NAME		"__AUL_SERVICE_NAME__"

/** AUL public key - To force launch app selector instead of lauchingn default app */
#define AUL_K_FORCE_LAUNCH_APP_SELECTOR	"__AUL_FORCE_LAUNCH_APP_SELECTOR__"

/** AUL public key - To support SDK */
#define AUL_K_SDK	"__AUL_SDK__"

/** AUL public key - To support Media key */
#define AUL_K_MULTI_KEY	"__AUL_MULTI_KEY__"
/** AUL public key - To support Media key */
#define AUL_K_MULTI_KEY_EVENT	"__AUL_MULTI_KEY_EVENT__"

/** AUL public bundle value - To support Media key*/
#define AUL_V_KEY_PRESSED	"__AUL_KEY_PRESSED__"
/** AUL public bundle value - To support Media key*/
#define AUL_V_KEY_RELEASED	"__AUL_KEY_RELEASED__"

/** AUL internal private key */
#define AUL_K_EXEC		"__AUL_EXEC__"
/** AUL internal private key */
#define AUL_K_MULTIPLE		"__AUL_MULTIPLE__"
/** AUL internal private key */
#define AUL_K_PACKAGETYPE	"__AUL_PACKAGETYPE__"
/** AUL internal private key */
#define AUL_K_HWACC		"__AUL_HWACC__"
/** AUL internal private key */
#define AUL_K_TASKMANAGE	"__AUL_TASKMANAGE__"


/** AUL internal private key */
#define AUL_K_APPID		"__AUL_APPID__"
/** AUL internal private key */
#define AUL_K_PID		"__AUL_PID__"
/** AUL internal private key */
#define AUL_K_WID		"__AUL_WID__"
/** AUL internal private key */
#define AUL_K_LEADER_PID	"__AUL_LEADER_PID__"

/** AUL internal private key */
#define AUL_K_PRELAUCHING	"__AUL_PRELAUCHING__"

/** AUL internal private key */
#define AUL_K_OWNER_PID		"__AUL_OWNER_PID__"
/** AUL internal private key */
#define AUL_K_CHILD_PID		"__AUL_CHILD_PID__"

#ifdef _APPFW_FEATURE_PROCESS_POOL
#define AUL_K_INTERNAL_POOL "__AUL_INTERNAL_POOL__"
#endif

#ifdef _APPFW_FEATURE_DATA_CONTROL
#define AUL_K_DATA_CONTROL_TYPE   "__AUL_DATA_CONTROL_TYPE__"
#endif

/** AUL internal private key */
#define AUL_K_HOST_PID	"__AUL_HOST_PID__"

/** Internal operation for launching application which is other zone */
#define AUL_SVC_OPERATION_JUMP	"http://tizen.org/appcontrol/operation/jump"
#define AUL_SVC_K_JUMP_ZONE_NAME	"__K_JUMP_DOMAIN_NAME__"
#define AUL_SVC_K_JUMP_ORIGIN_OPERATION	"__K_JUMP_ORIGIN_OPERATION__"
#define AUL_SVC_K_FOCUS_ZONE "__K_FOCUS_ZONE__"
#define AUL_SVC_K_RUA_STAT_CALLER		"__K_RUA_STAT_CALLER__"
#define AUL_SVC_K_RUA_STAT_TAG		"__K_RUA_STAT_TAG__"


#define AUL_K_ALLOWED_BG	"__AUL_INTERNAL_ALLOWED_BG__"

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#define AUL_TEP_PATH			"_AUL_TEP_PATH_"
int aul_check_tep_mount(const char *tep_path);
int aul_is_tep_mount_dbus_done(const char *tep_string);
#endif


/** AUL internal private key */
#define AUL_K_PKGID		"__AUL_PKGID_"


/**
 * @brief	This is callback function for aul_launch_init
 * @param[in]	type    event's type received from system
 * @param[in]	b	In case of RESET events, bundle which is received from peer
 * @param[in]	data	user-supplied data
 */
typedef int (*aul_handler_fn) (aul_type type, bundle * b, void *data);

/**
 * @par Description:
 *	This API install your AUL handler and setup AUL internal connection.
 * @par Purpose:
 *      AUL receive START(RESET), RESUME, TERMINATE events from system.\n
 *      This API use to handle the events. \n
 * @par Typical use case:
 *	In general, you need not use this API.
 *      If you use AppCore, you should NOT use this API.
 *      AppCore will set default aul_handler.
 *
 * @param[in]	handler		aul main callback handler function
 * @param[in]	data		user-supplied data for start_handler
 * @return	0 if success, negative value(<0) if fail\n
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ECANCELD	- aul handler was installed already by others
 * @retval	AUL_R_ECOMM	- error to create internal ipc
 * @retval	AUL_R_ERROR	- error to attach glib main loop or ecore main loop
 *
 * @warning	If you use AppCore, you should NOT use this API.\n
 *		You need glib main loop or ecore main loop.\n
 * @pre
 *	you must have aul handler to use this API.
 *	aul_luanch_init register aul handler.
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * static int aul_handler(aul_type type, bundle *kb,void *data)
 * {
 *	switch(type)
 *      {
 *	        case AUL_START:
 *			// process RESET event
 *	                break;
 *		case AUL_RESUME:
 *	                // process RESUME event
 *		        break;
 *	        case AUL_TERMINATE:
 *		        // preocess TERMINATE event
 *	                break;
 *      }
 *      return 0;
 * }
 *
 * int main(int argc, char **argv)
 * {
 *	ecore_init();
 *      aul_launch_init(aul_handler,NULL);
 *      aul_launch_argv_handler(argc, argv);
 *	ecore_main_loop_begin();
 * }
 *
 * @endcode
 * @remark
 *	None
*/
int aul_launch_init(aul_handler_fn handler, void *data);

/**
 * @par Description:
 *	This API create internal RESET events with given argc, argv \n
 * @par Purpose:
 *      This API's purpose is to generate reset event.
 *      If you want to generate local RESET events with argument vector format, use this API
 * @par Typical use case:
 *	In general, you need not use this API.
 *	AppCore use this API to create internal reset event.
 *
 * @param[in]	argc	# of args
 * @param[in]	argv	list of arg strings
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ENOINIT	- aul handler was NOT yet installed
 * @retval	AUL_R_ECANCLED	- error to create internal bundle with given argc,argv.
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	you must have aul handler to use this API.
 *	aul_luanch_init register aul handler.
 * @post
 *	None
 * @see
 *	aul_launch_init
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int send_local_reset_event()
 * {
 *	int argc=3;
 *	char* argv[4];
 *	argv[0] = "local.app";
 *	argv[1] = "event_type";
 *	argv[2] = "my_reset";
 *	argv[3] = NULL;
 *	aul_launch_argv_handler(argc,argv);
 * }
 *
 * @endcode
 * @remark
 *      If you use AppCore, you NEED NOT use this API.
*/
int aul_launch_argv_handler(int argc, char **argv);

/**
 * @par Description:
 *	This API create internal RESET events with given argc, argv \n
 * @par Purpose:
 *      This API's purpose is to generate reset event.
 *      If you want to generate local RESET events with argument vector format, use this API
 * @par Typical use case:
 *	In general, you need not use this API.
 *	AppCore use this API to create internal reset event.
 *
 * @param[in]	argc	# of args
 * @param[in]	argv	list of arg strings
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ENOINIT	- aul handler was NOT yet installed
 * @retval	AUL_R_ECANCLED	- error to create internal bundle with given argc,argv.
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	you must have aul handler to use this API.
 *	aul_luanch_init register aul handler.
 * @post
 *	None
 * @see
 *	aul_launch_init
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int send_local_reset_event()
 * {
 *	int argc=3;
 *	char* argv[4];
 *	argv[0] = "local.app";
 *	argv[1] = "event_type";
 *	argv[2] = "my_reset";
 *	argv[3] = NULL;
 *	aul_launch_argv_handler_for_efl(argc,argv);
 * }
 *
 * @endcode
 * @remark
 *      If you use AppCore, you NEED NOT use this API.
*/
int aul_launch_argv_handler_for_efl(int argc, char **argv);


/**
 * @par Description:
 *	This API creates internal RESET events with given bundle \n
 * @par Purpose:
 *  This API's purpose is to generate reset event.
 *  If you want to generate local RESET events with argument vector format, first use
 *  bundle_import_from_argv to create a bundle from the argument vector and then use this API
 *  Eventually, this API will replace aul_launch_argv_handler().
 * @par Typical use case:
 *	In general, you need not use this API.
 *	AppCore use this API to create internal reset event.
 *
 * @param[in]	b	bundle
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ENOINIT	- aul handler was NOT yet installed
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	you must have aul handler to use this API.
 *	aul_luanch_init register aul handler.
 * @post
 *	None
 * @see
 *	aul_launch_init, bundle_import_from_argv
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int send_local_reset_event()
 * {
 *  bundle* b;
 *	int argc=3;
 *	char* argv[4];
 *	argv[0] = "local.app";
 *	argv[1] = "event_type";
 *	argv[2] = "my_reset";
 *	argv[3] = NULL;
 *
 *	b = bundle_import_from_argv(argc,argv);
 *	aul_launch_local(b);
 * }
 *
 * @endcode
 * @remark
 *      If you use AppCore, you NEED NOT to use this API.
*/
int aul_launch_local(bundle *b);

/**
 * @par Description:
 *	This API launches application with the given bundle.
 *  If the application is not running or a multiple-instance one, this API launches with the given bundle.
 *	If the application is running, this API sends a RESET event to the App.
 *	While the application is running, if the application cannot receive the RESET event,
 *	this API returns a general error(AUL_R_ERROR).\n
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to launch/reset application with given bundle.
 * @par Typical use case:
 *	If you know the target application's pkgname and bundle types,
 *	you can use this API to launch/reset the application.
 *
 * @param[in]	pkgname		package name to be run as callee
 * @param[in]	kb		bundle to be passed to callee
 * @return	callee's pid if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild package name
 * @retval	AUL_R_ECOMM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	aul_open_app
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int launch_inhouse_contact_app()
 * {
 *	bundle *b;
 *	b = bundle_create();
 *	bundle_add(b,"type","SIM");
 *	aul_launch_app("org.tizen.contact",b);
 *	iuu
 * }
 *
 * @endcode
 * @remark
 *	None
 */
int aul_launch_app(const char *appid, bundle *kb);

/**
 * @par Description:
 *  This API launches application, as menu screen launches the app.
 *  Thus, if the applocation is running, this API sends a RESUME event to the app.
 *  If the application is not running, this API launches the app.
 *  While the application is running, if the application cannot receive the RESUME event,
 *  AUL tries to raise the application's default window.
 *
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to resume/launch application
 * @par Typical use case:
 *	If you only want to show application with previous state or default state, Use this API.
 *
 * @param[in]	pkgname		package name to be resume as callee
 * @return	callee's pid if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild package name
 * @retval	AUL_R_ECOMM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	aul_launch_app, aul_app_is_running, aul_resume_pid
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int open_inhouse_contact_app()
 * {
 *	if(aul_app_is_running("org.tizen.contact"))
 *		aul_open_app("org.tizen.contact");
 * }
 *
 * @endcode
 * @remark
 *	If you don't want to launch the app,
 *	you should check app's running state with aul_app_is_running.
 *	This API will launch the application if the application is not running.
*/
int aul_open_app(const char *appid);

/**
 * @par Description:
 *	This API trigger to resume application
 * 	If the application is running, this API send a resume event to the App.
 *	If the application is not running, this API returns fail.
 *	Although the application is running, if the application cannot receive resume event,
 *	AUL try to raise the application's default windows.
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to send resume event.
 * @par Typical use case:
 *	If you only want to show application with previous state or default state, Use this API.
 *
 * @param[in]	pkgname		package name to be resume as callee
 * @return	callee's pid if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild package name
 * @retval	AUL_R_ECOMM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	aul_launch_app, aul_app_is_running, aul_resume_pid
 * @deprecated
 *  This function will be deprecated. Use aul_open_add() instead.
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int resume_inhouse_contact_app()
 * {
 *	if(aul_app_is_running("org.tizen.contact"))
 *		aul_resume_app("org.tizen.contact");
 * }
 *
 * @endcode
 * @remark
 *	If you don't want to launch the app,
 *	you should check app's running state with aul_app_is_running.
 *	This API will launch the application if the application is not running.
 *	If you want to only resume without launching in multiple instance application model,
 *	you should use aul_resume_pid.
*/
int aul_resume_app(const char *appid);

/**
 * @par Description:
 *	This API trigger to resume application
 *	If the application is running, this API send a resume event to the App.
 *	If the application is not running, this API return AUL_R_ERROR.
 *	Although the application is running, if the application cannot receive resume event,
 *	AUL try to raise the application's default windows.
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to send resume event.
 * @par Typical use case:
 *	In multiple application model, If you want to only resume specific application, Use this API
 *
 * @param[in]	pid	application's pid to be resumed
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild pid
 * @retval	AUL_R_ECOMM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error (include application is not running)
 * @warning	This API need to require root or inhouse permisssion \n
 *		If you have not the permission, this API return AUL_R_ERROR. \n
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	aul_launch_app
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int iterfunc(const aul_app_info *info, void *data)
 * {
 *	if(strcmp(info->pkg_name,"org.tizen.contact")==0)
 *		aul_resume_pid(info->pid);
 * }
 *
 * int iterate_running_apps()
 * {
 *      return aul_app_get_running_app_info(iterfunc,NULL);
 * }
 *
 * @endcode
 * @remark
 *	None
*/
int aul_resume_pid(int pid);

/**
 * @par Description:
 *	This API trigger to terminate application
 *
 *	If the application is running, this API send a terminate event to the App. \n
 *	If the app cannot receive the event, AUL kill forcely the application.\n
 * @par Purpose:
 *      This API's purpose is to kill application
 * @par Typical use case:
 *	In general, Application like Task Manager use this API.
 *
 *		This API need to require root or inhouse permisssion. \n
 *
 * @param[in]	pid	application's pid to be terminated
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild pid
 * @retval	AUL_R_ECOMM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 * @warning	This API need to require root or inhouse permisssion. \n
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int iterfunc(const aul_app_info *info, void *data)
 * {
 *	if(strcmp(info->pkg_name,"org.tizen.contact")==0)
 *		aul_terminate_pid(info->pid);
 * }
 *
 * int iterate_running_apps()
 * {
 *      return aul_app_get_running_app_info(iterfunc,NULL);
 * }
 *
 * @endcode
 * @remark
 *	If you have not the permission, this API return AUL_R_ERROR. \n
*/
int aul_terminate_pid(int pid);
int aul_terminate_bgapp_pid(int pid);
int aul_terminate_pid_without_restart(int pid);
int aul_terminate_pid_async(int pid);


/** @} */

/**
 * @defgroup aul_info		Helper APIs to get running application information
 * @ingroup aul
 * @brief
 *	API to get running application information (state, executable path, ..)
 *	- get application package name from pid
 *	- get application running state
 *	- get application list of runnning applications
 */

/**
 * @addtogroup aul_info
 * @{
 */

/**
 *@brief Running application's information structure retrieved by AUL
 */
typedef struct _aul_app_info {
	int pid;		/**< app's pid if running*/
	char* pkg_name;		/**< application id */
	char* app_path;		/**< application excutable path */
	char* appid;
} aul_app_info;

/**
 * @brief iterator function running with aul_app_get_running_app_info
 * @param[out]	ainfo   aul_app_info retreived by aul_app_get_running_app_info
 * @param[out]	data	user-supplied data
*/
typedef int (*aul_app_info_iter_fn)(const aul_app_info *ainfo, void *data);

/**
 * @par Description:
 *	This API ask a application is running by application package name.
 * @par Purpose:
 *	To know whether some application is running or not, use this API
 * @par Typical use case:
 *	For example, If you want to know browser application running,
 *	you can check it by using this API.
 *
 * @param[in]	pkgname	application package name
 * @return	true / false
 * @retval	1	app_name is running now.
 * @retval	0	app_name is NOT running now.
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 *
 * int is_running_browser_app()
 * {
 *      return aul_app_is_running("org.tizen.browser");
 * }
 *
 * @endcode
 * @remark
 *	None
*
*/
int aul_app_is_running(const char *appid);

/**
 * @par Description:
 *	This API use to get running application list.
 *	This API call iter_fn with each aul_app_info of running apps when running application is found.
 * @par Purpose:
 *	If you want to get running application list, use this API
 *	This API give you running applications which has SLP desktop file.
 * @par Typical use case:
 *	In general, this API is used by task manager appllication. (running application list viewer)
 *
 * @param[in]	iter_fn		iterator function
 * @param[in]	data		user-supplied data for iter_fn
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- internal error
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 *
 * int iterfunc(const aul_app_info* info, void* data)
 * {
 *	printf("\t==========================\n");
 *	printf("\t pkg_name: %s\n", info->appid);
 *	printf("\t app_path: %s\n", info->app_path);
 *	printf("\t running pid: %d\n", info->pid);
 *	printf("\t==========================\n");
 *	return 0;
 * }
 *
 * int iterate_running_apps()
 * {
 *      return aul_app_get_running_app_info(iterfunc,NULL);
 * }
 *
 * @endcode
 * @remark
 *	This API should use if you want to know running application which has desktop files.
 *	If you want to get all process list, you must iterate process information by using proc filesystem
 *	Or, If you want to get all window list, you must iterate XWindows by using XWindow APIs
 */
int aul_app_get_running_app_info(aul_app_info_iter_fn iter_fn, void *data);

/**
 * @par Description:
 *	This API use to get running application list from the proc file system.
 *	This API call iter_fn with each aul_app_info of running apps when running application is found.
 *
 * @param[in]	iter_fn		iterator function
 * @param[in]	data		user-supplied data for iter_fn
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- internal error
 */
int aul_get_running_app_info_from_proc(aul_app_info_iter_fn iter_fn, void *data);

int aul_get_running_app_info_from_memory(aul_app_info_iter_fn iter_fn, void *data);


/**
 * @par Description:
 *	This API get application package name by pid
 * @par Purpose:
 *	If you want to get package name of running application, use this API
 * @par Typical use case:
 *	In general, You can use this API when you want to know caller's information.
 *
 * @param[in]	pid		given pid
 * @param[out]	pkgname		pkgname to be get
 * @param[in]	len		length of pkgname
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- no such a package name
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * static int app_reset(bundle *b, void *data)
 * {
 *	int pid;
 * 	char appname[255];
 *
 * 	pid = atoi(bundle_get_val(b,AUL_K_CALLER_PID));
 *	aul_app_get_pkgname_bypid(pid, appname, sizeof(appname));
 * }
 *
 * @endcode
 * @remark
 *	None
*/
int aul_app_get_pkgname_bypid(int pid, char *pkgname, int len);

/**
 * @par Description:
 *	This API get application appid by pid
 * @par Purpose:
 *	If you want to get appid of running application, use this API
 * @par Typical use case:
 *	In general, You can use this API when you want to know caller's information.
 *
 * @param[in]	pid		given pid
 * @param[out]	appid		application id
 * @param[in]	len		length of pkgname
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- no such a appid
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * static int app_reset(bundle *b, void *data)
 * {
 *	int pid;
 * 	char appid[255];
 *
 * 	pid = atoi(bundle_get_val(b,AUL_K_CALLER_PID));
 *	aul_app_get_appid_bypid(pid, appid, sizeof(appid));
 * }
 *
 * @endcode
 * @remark
 *	None
*/
int aul_app_get_appid_bypid(int pid, char *appid, int len);

int aul_app_get_pkgid_bypid(int pid, char *pkgid, int len);


/** @} */

/**
 * @defgroup aul_mime High-level APIs to launch default application based on mime type
 * @ingroup aul
 * @brief
 *   AUL High-level APIs based on mime type
 *
 *   These APIs provide two functionality\n
 *
 *   -# To launch default application to open a file based on its MIME type \n
 *   For example, you can launch the default video player to open .mp4 files
 *   or launch the default browser to open HTML files \n
 *   -# To launch default application to process given content \n
 *   For example, you can launch the default e-mail application to process
 *   "nice@samsung.com" e-mail address.
 */

/**
 * @addtogroup aul_mime
 * @{
 */

/**
 * @par Description:
 *	This API get the mimetype associated with filename
 * @par Purpose:
 *	This API use to get mimetype associteted with given filename
 *	In general, This API use when you want to know only mimetype given filename.
 * @par Typical use case:
 *	For example, In trasfering data through bluetooth,
 *	additional information like mimetype should be added.
 *	In such situation, You can get mimetype by using this API.
 *
 * @param[in]	filename	file name
 * @param[out]	mimetype	a mime type
 * @param[in]	len		length of mimetype
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(filename)
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 *
 * void get_mimetype()
 * {
 *	char mimetype[255];
 *	aul_get_mime_from_file("image.jpg",mimetype,sizeof(mimetype));
 * }
 *
 * @endcode
 * @remark
 *	None
 */
int aul_get_mime_from_file(const char *filename, char *mimetype, int len);

/**
 * @par Description:
 *	This API get the mimetype associated with given content
 * @par Purpose:
 *	This API use to get mimetype associteted with given content
 *	In general, This API use when you want to know only mimetype given content
 * @par Typical use case:
 *	For example, In trasfering data through bluetooth,
 *	additional information like mimetype should be added.
 *	In such situation, You can get mimetype by using this API.
 *
 * @param[in]	content		content string like "011-0000-0000"
 * @param[out]	mimetype	a mime type
 * @param[in]	len		length of mimetype
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(content)
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 *
 * void get_mimetype()
 * {
 *	char mimetype[255];
 *	aul_get_mime_from_content("http://www.samsung.com",mimetype,sizeof(mimetype));
 * }
 *
 * @endcode
 * @remark
 *	None
*/
int aul_get_mime_from_content(const char *content, char *mimetype, int len);

/**
 * @par Description:
 *	This API get the icon's name associated with given mimetype
 * @par Purpose:
 *	This API use to get icon's name associteted with given mimetype
 * @par Typical use case:
 *	If you want to show mimetype's icon, use this API.
 *
 * @param[in]	mimetype	a mime type
 * @param[out]	iconname	icon's name
 * @param[in]	len		length of iconname
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(content)
 * @retval	AUL_R_ERROR	- general error (no such mime type)
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	None
 * @code
 * #include <aul.h>
 *
 * void get_mime_icon()
 * {
 *	char icon[255];
 *	aul_get_mime_icon("text/html",icon,sizeof(icon));
 * }
 *
 * @endcode
 * @remark
 *	None
 */
int aul_get_mime_icon(const char *mimetype, char *iconname, int len);

/**
 * @par Description:
 *	This API get the extensions associated with given mimetype
 * @par Purpose:
 *	This API use to get extensions associteted with given mimetype
 * @par Typical use case:
 *	In general, user is not familiar with mimetype(text/html),
 *	user is familiar with extenstions(*.html, *.htm)
 *	So, To show mimetype information to user, use this API
 *
 * @param[in]	mimetype	a mime type
 * @param[out]	extlist		extentions (ex> mpeg,mpg,mpe)
 * @param[in]	len		length of extlist
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(mimetype)
 * @retval	AUL_R_ERROR	- general error (no mimetype or no extenstion)
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	aul_get_mime_description
 * @code
 * #include <aul.h>
 *
 * void get_extension()
 * {
 *	char extlist[255];
 *	aul_get_mime_extension("text/html",extlist,sizeof(extlist));
 * }
 *
 * @endcode
 * @remark
 *	Some mimetype don't have extension.
 *	In that case, You can use aul_get_mime_description.
 *
*/
int aul_get_mime_extension(const char *mimetype, char *extlist, int len);

/**
 * @par Description:
 *	This API get the description associated with given mimetype
 * @par Purpose:
 *	This API use to get description associteted with given mimetype
 * @par Typical use case:
 *	In general, user is not familiar with mimetype(text/html),
 *	user is familiar with well-knowing information like extenstions(*.html, *.htm)
 *	But, some mimetype don't have extenstion.
 *	At that time,to show mimetype information to user, use this API
 *
 * @param[in]	mimetype	a mime type
 * @param[out]	desc		description (ex> Call client)
 * @param[in]	len		length of desc
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(mimetype)
 * @retval	AUL_R_ERROR	- general error (no mimetype or no descrition)
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	aul_get_mime_extension
 * @code
 * #include <aul.h>
 *
 * void get_information_from_mime()
 * {
 *	char info[255];
 *	if(aul_get_mime_extension("text/html",info,sizeof(info))<0){
 *		aul_get_mime_description("text/html",info,sizeof(info));
 *	}
 * }
 *
 * @endcode
 * @remark
 *	None
 */
int aul_get_mime_description(const char *mimetype, char *desc, int len);

/** @} */

/**
 * @defgroup aul_service High-level APIs to launch applications based on service.
 * @ingroup aul
 * @brief
 *      AUL High-level APIs based on service
 *
 *	This is Request/Response mechanism based on AUL like DBUS service call with auto-activation.\n
 *	We recommend this APIs for requesting application service like camera application service (take_picture)
 *	But, You can use other mechanism like DBUS service or your own internal IPC
 *
 *      - Caller\n
 *        Launch application based on service \n
 *        If application is not running, AUL requests to reset the event.\n
 *        Application can wait result with callback function.
 *
 *      - Callee\n
 *        After callee performs the requested operation, callee sends the result back, if necessary.\n
 *
 */

/**
 * @addtogroup aul_service
 * @{
 */

/**
 * @brief aul_service_res_fn is service result function
 * @param[out]	b   	result bundle
 * @param[out]	data	user-supplied data
*/
typedef void (*aul_service_res_fn)(bundle *b, int reserved, void *user_data);

/**
 * @par Description:
 *	This API create service result bundle based on bundle received in reset event.
 * @par Purpose:
 *	This API use to create result bundle to send it to caller.
 * @par Typical use case:
 *	This API is for callee which provide application service.\n
 *      To send result to caller, You must create result bundle. \n
 *      Callee(application providing the service) can send result by using this API and aul_send_service_result.
 *
 * @param[in]   inb             bundle received in reset event
 * @param[out]  outb            bundle to use for returning result
 * @return      0 if success, negative value(<0) if fail
 * @retval      AUL_R_OK        - success
 * @retval      AUL_R_EINVAL    - inb is not bundle
 * @retval      AUL_R_ERROR     - general error
 *
 * @pre
 *	To create result bundle, You need received original bundle.
 *	The original bundle can get from app_reset handler.
 * @post
 *	None
 * @see
 *	aul_send_service_result
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int app_reset(bundle *b, void *data)
 * {
 *      ad->recved_bundle = bundle_dup(b);
 * }
 *
 * int click_ok()
 * {
 *      bundle* res_bundle;
 *      aul_create_result_bundle(ad->recved_bundle,&res_bundle);
 *      bundle_add(res_bundle, "result", "1");
 *      aul_send_service_result(res_bundle);
 * }
 * @endcode
 * @remark
 *	None
 *
 */
int aul_create_result_bundle(bundle *inb, bundle **outb);

/**
 * @par Description:
 *	This API send service result to caller with bundle
 * @par Purpose:
 *	This API is used to send result bundle to caller.
 * @par Typical use case:
 *	This API is for callee which provide application service.\n
 *      To send result to caller, You can use this API after creating result bundle. \n
 *      Callee(application to provide service) can send result by using this API and aul_create_result_bundle.
 *
 * @param[in]   b      Result data in bundle format
 * @return      0 if success, negative value(<0) if fail
 * @retval      AUL_R_OK        - success
 * @retval      AUL_R_EINVAL    - invalid result bundle
 * @retval      AUL_R_ECOMM     - internal AUL IPC error
 * @retval      AUL_R_ERROR     - general error
 *
 * @pre
 *	To send result bundle, You must create result bundle.
 *      see aul_create_result_bundle
 * @post
 *	None
 * @see
 *	aul_create_result_bundle
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int app_reset(bundle *b, void *data)
 * {
 *      ad->recved_bundle = bundle_dup(b);
 * }
 *
 * int click_ok()
 * {
 *      bundle* res_bundle;
 *      aul_create_result_bundle(ad->recved_bundle,&res_bundle);
 *      bundle_add(res_bundle, "result", "1");
 *      aul_send_service_result(res_bundle);
 * }
 * @endcode
 * @remark
 *	None
 *
 */
int aul_send_service_result(bundle *b);

/**
 * @par Description:
 *	This API sets callback fuction that will be called when applications die.
 * @par Purpose:
 *	This API's purpose is to listen the application dead event.
 *	In general, task manager Application need this API.
 *
 * @param[in]	func		callback function
 * @param[in]	data		user data
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	aul_listen_app_launch_signal
 * @code
 * #include <aul.h>
 *
 * int app_dead_handler(int pid, void *data)
 * {
 * 	printf("===> %s : %d\n", __FUNCTION__, pid);
 * 	return 0;
 * }
 *
 * void dead_listen()
 * {
 *	aul_listen_app_dead_signal(app_dead_handler, NULL);
 * }
 *
 * @endcode
 * @remark
 *	None
 *
 */
int aul_listen_app_dead_signal(int (*func) (int, void *), void *data);

/**
 * @par Description:
 *	This API sets callback fuction that will be called when applications are launched.
 * @par Purpose:
 *	This API's purpose is to listen the application launching event.
 *	In general, task manager Application need this API.
 *
 * @param[in]	func		callback function
 * @param[in]	data		user data
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	None
 * @post
 *	None
 * @see
 *	aul_listen_app_dead_signal
 * @code
 * #include <aul.h>
 *
 * int app_launch_handler(int pid, void *data)
 * {
 * 	printf("===> %s : %d\n", __FUNCTION__, pid);
 * 	return 0;
 * }
 *
 * void dead_listen()
 * {
 *	aul_listen_app_launch_signal(app_launch_handler, NULL);
 * }
 *
 * @endcode
 * @remark
 *	None
 *
 */
int aul_listen_app_launch_signal(int (*func) (int, void *), void *data);

int aul_listen_booting_done_signal(int (*func) (int, void *), void *data);

int aul_listen_cooldown_signal(int (*func) (const char *, void *), void *data);

const char *aul_get_app_external_root_path(void);
const char *aul_get_app_root_path(void);
const char *aul_get_app_data_path(void);
const char *aul_get_app_cache_path(void);
const char *aul_get_app_resource_path(void);
const char *aul_get_app_tep_resource_path(void);
const char *aul_get_app_shared_data_path(void);
const char *aul_get_app_shared_resource_path(void);
const char *aul_get_app_shared_trusted_path(void);
const char *aul_get_app_external_data_path(void);
const char *aul_get_app_external_cache_path(void);
const char *aul_get_app_external_shared_data_path(void);
const char *aul_get_app_specific_path(void);
const char *aul_get_app_external_specific_path(void);
int aul_get_app_shared_data_path_by_appid(const char *app_id, char **path);
int aul_get_app_shared_resource_path_by_appid(const char *app_id, char **path);
int aul_get_app_shared_trusted_path_by_appid(const char *app_id, char **path);
int aul_get_app_external_shared_data_path_by_appid(const char *app_id, char **path);

typedef int (*subapp_fn)(void *data);

int aul_set_subapp(subapp_fn cb, void *data);
int aul_subapp_terminate_request_pid(int pid);
int aul_is_subapp(void);
int aul_add_caller_cb(int pid,  void (*caller_cb) (int, void *), void *data);
int aul_remove_caller_cb(int pid);
int aul_invoke_caller_cb(int pid);

#ifdef _APPFW_FEATURE_PROCESS_POOL
void aul_set_preinit_window(void *evas_object);
void* aul_get_preinit_window(const char *win_name);

void aul_set_preinit_background(void *evas_object);
void* aul_get_preinit_background(void);

void aul_set_preinit_conformant(void *evas_object);
void* aul_get_preinit_conformant(void);
#endif

void aul_set_preinit_appid(const char *appid);

void aul_set_preinit_pkgid(const char *pkgid);
const char* aul_get_preinit_pkgid(void);

int aul_launch_app_async(const char *appid, bundle *kb);

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
int aul_launch_app_for_multi_instance(const char *appid, bundle *kb);
#endif

int aul_update_freezer_status(int pid, const char* type);

int aul_send_app_launch_request_signal(int pid, const char* appid, const char* pkgid, const char* type);
int aul_send_app_resume_request_signal(int pid, const char* appid, const char* pkgid, const char *type);
int aul_send_app_terminate_request_signal(int pid, const char* appid, const char* pkgid, const char *type);
int aul_send_app_status_change_signal(int pid, const char* appid, const char* pkgid, const char* status, const char *type);
int aul_send_app_terminated_signal(int pid);
int aul_send_app_group_signal(int owner_pid, int child_pid, const char *child_pkgid);

int aul_status_update(int status);

/**
 * @par Description:
 *	This API gets status of specified application process id.
 * @par Purpose:
 *	This API's purpose is to get the application's status.
 *
 * @param[in]	pid	pid of application
 * @return	0 or greater if success, nagative value if fail
 * @retval	STATUS_LAUNCHING
 * @retval	STATUS_CREATED
 * @retval	STATUS_FOCUS
 * @retval	STATUS_VISIBLE
 * @retval	STATUS_BG
 * @retval	STATUS_DYING
 * @retval	STATUS_HOME
 * @retval	STATUS_NORESTART
 * @see
 *	aul_status_update
 * @pre
 * 	None
 * @post
 * 	None
 * @code
 * #include <aul.h>
 *
 * int iterfunc(const aul_app_info *info, void *data)
 * {
 *	int status;
 *	status = aul_app_get_status_bypid(info->pid);
 *	if (status == STATUS_FOCUS) {
 *		printf("%s has focus", info->app_id);
 *		(int *)data = info->pid;
 *		return -1;
 *	}
 *	return 0;
 * }
 *
 * int find_focus_app_pid()
 * {
 *	int pid = 0;
 *	aul_app_get_running_app_info(iterfunc, &pid);
 *	return pid;
 * }
 * @endcode
 * @remark
 *	None
 */
int aul_app_get_status_bypid(int pid);

/**
 * @par Description
 * 	This API sets callback function that on application status changed.
 * @par Purpose:
 *	This API's purpose is to listen the application's status changed within
 *	the caller process. In general, a library that required to release resource on
 *	application's status may use this API.
 *
 * @param[in]	func	callback function
 * @param[in]	data	user data
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- general error
 * @see
 *	aul_remove_status_local_cb
 * @pre
 *	None
 * @post
 * 	None
 * @code
 * #include <aul.h>
 *
 * int status_changed(int status, void *data)
 * {
 *	if (status == STATUS_FOCUS)
 *		printf("%d has focus\n", getpid());
 *
 *	if (status == STATUS_VISIBLE)
 *		printf("%d resume\n", getpid());
 *
 *	if (status == STATUS_BG0
 *		printf("%d pause\n", getpid());
 * }
 *
 * void listen_app_status()
 * {
 *	aul_add_status_local_cb(status_changed, NULL);
 * }
 * @endcode
 * @remark
 * 	None
 *
 */
int aul_add_status_local_cb(int (*func) (int, void *), void *data);

/**
 * @par Description
 * 	This API unsets callback function that on application status changed.
 * @par Purpose:
 *	This API's purpose is to remove callback that added by
 *	aul_add_status_local_cb.
 *
 * @param[in]	func	callback function
 * @param[in]	data	user data
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	None
 * @post
 * 	None
 * @see
 *	aul_add_status_local_cb
 * @code
 * #include <aul.h>
 *
 * int status_changed(int status, void *data)
 * {
 *	if (status == STATUS_FOCUS)
 *		printf("%d has focus\n", getpid());
 *
 *	if (status == STATUS_VISIBLE)
 *		printf("%d resume\n", getpid());
 *
 *	if (status == STATUS_BG0
 *		printf("%d pause\n", getpid());
 * }
 *
 * void listen_app_status()
 * {
 *	aul_add_status_local_cb(status_changed, NULL);
 * }
 *
 * void ignore_app_status()
 * {
 *	aul_remove_status_local_cb(status_changed, NULL);
 * }
 *
 * @endcode
 * @remark
 * 	None
 *
 */
int aul_remove_status_local_cb(int (*func) (int, void *), void *data);

int aul_invoke_status_local_cb(int status);

int aul_running_list_update(char *appid, char *app_path, char *pid);

int aul_get_app_allocated_memory(void);

long long aul_get_app_running_time(void);

int aul_app_get_cmdline_bypid(int pid, char *cmdline, int len);

int aul_listen_e17_status_signal(int (*func) (int, int, void *), void *data);

#ifdef _APPFW_FEATURE_DATA_CONTROL
typedef int (*data_control_provider_handler_fn) (bundle *b, int request_id, void *data);
int aul_set_data_control_provider_cb(data_control_provider_handler_fn handler);
int aul_unset_data_control_provider_cb(void);
#endif
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
int aul_call_ug_result_callback(bundle *kb, int is_cancel, int id);
#endif

int aul_get_support_legacy_lifecycle(void);

char *aul_get_cmdline_bypid(int pid);

int aul_app_group_get_window(int pid);
int aul_app_group_set_window(int wid);
void aul_app_group_get_leader_pids(int *cnt, int **pids);
void aul_app_group_get_group_pids(int leader_pid, int *cnt, int **pids);
int aul_app_group_get_leader_pid(int pid);
int aul_app_group_clear_top(void);
int aul_app_group_is_top(void);
int aul_app_group_get_fg_flag(int pid);
void aul_app_group_lower(int *exit);
void aul_app_group_get_idle_pids(int *cnt, int **pids);

char *aul_get_group_info(void);

int aul_pause_app(const char *appid);
int aul_pause_pid(int pid);
int aul_app_get_pid(const char *appid);
int aul_app_get_pid_cache(const char *appid);

int aul_app_get_last_caller_pid(int pid);

int aul_set_process_group(int parent_pid, int child_pid);
/** @} */



#ifdef __cplusplus
	}
#endif


#endif		/* __AUL_H__ */

/* vi: set ts=8 sts=8 sw=8: */
