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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <glib.h>
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
#include <pkgmgr-info.h>
#include <pkgmgrinfo_zone.h>
#endif
#include <ttrace.h>
#include <bundle_internal.h>

#include "aul.h"
#include "aul_api.h"
#include "app_sock.h"
#include "perf.h"
#include "simple_util.h"
#include "launch.h"
#include "key.h"
#include "aul_util.h"
#include "aul_zone.h"
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#include <dbus/dbus.h>
#include "app_signal.h"
#define TEP_ISMOUNT_MAX_RETRY_CNT 20
#endif

static int aul_initialized = 0;
static int aul_fd;

static int (*_aul_handler) (aul_type type, bundle *kb, void *data) = NULL;
static void *_aul_data;


static int app_resume();
static int app_terminate();
static void __clear_internal_key(bundle *kb);
static inline void __set_stime(bundle *kb);
static int __app_start_internal(gpointer data);
static int __app_launch_local(bundle *b);
static int __send_result_to_launchpad(int fd, int res);

#ifdef _APPFW_FEATURE_PROCESS_POOL
static void *__window_object = NULL;
static void *__bg_object = NULL;
static void *__conformant_object = NULL;
#endif

#ifdef _APPFW_FEATURE_DATA_CONTROL
static data_control_provider_handler_fn __dc_handler = NULL;
#endif

extern  int aul_launch_fini();

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
SLPAPI int aul_is_tep_mount_dbus_done(const char *tep_string)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	int ret = -1;
	int r = -1;

	DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		_E("dbus_bus_get error");
		return -EBADMSG;
	}

	msg = dbus_message_new_method_call(TEP_BUS_NAME, TEP_OBJECT_PATH, TEP_INTERFACE_NAME, TEP_IS_MOUNTED_METHOD);
	if(!msg) {
		_E("dbus_message_new_method_call(%s:%s-%s)", TEP_OBJECT_PATH, TEP_INTERFACE_NAME, TEP_IS_MOUNTED_METHOD);
		return ret;
	}

	if (!dbus_message_append_args(msg,
					DBUS_TYPE_STRING, &tep_string,
					DBUS_TYPE_INVALID)) {
		_E("Ran out of memory while constructing args\n");
		dbus_message_unref(msg);
		return ret;
	}

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, 500, &err);
	if (!reply) {
		_E("dbus_connection_send error(%s:%s)", err.name, err.message);
		goto func_out;
	}

	r = dbus_message_get_args(reply, &err, DBUS_TYPE_INT32, &ret, DBUS_TYPE_INVALID);
	if (!r) {
		_E("no message : [%s:%s]", err.name, err.message);
		goto func_out;
	}

func_out :
	dbus_message_unref(msg);
	dbus_error_free(&err);
	return ret;
}

SLPAPI int aul_check_tep_mount(const char *tep_path)
{
	if(tep_path) {
		int rv = -1;
		int cnt = 0;
		while(cnt < TEP_ISMOUNT_MAX_RETRY_CNT) {
			rv = aul_is_tep_mount_dbus_done(tep_path);
			if(rv == 1)
				break;
			usleep(50 * 1000);
			cnt++;
		}
		/* incase after trying 1 sec, not getting mounted then quit */
		if( rv != 1) {
			_E("Not able to mount within 1 sec");
			return -1;
		}
	}
	return 0;
}
#endif

int aul_is_initialized()
{
	return aul_initialized;
}

int __call_aul_handler(aul_type type, bundle *kb)
{
	if (_aul_handler)
		_aul_handler(type, kb, _aul_data);
	return 0;
}

int app_start(bundle *kb)
{
	const char *str = NULL;

	_app_start_res_prepare(kb);
	__call_aul_handler(AUL_START, kb);

#ifdef _APPFW_FEATURE_DATA_CONTROL
	// Handle the DataControl callback
	str = bundle_get_val(kb, AUL_K_DATA_CONTROL_TYPE);
	if (str != NULL && strcmp(str, "CORE") == 0)
	{
		if (__dc_handler != NULL)
		{
			__dc_handler(kb, 0, NULL); // bundle, request_id, data
		}
	}
#endif
	return 0;
}

static int app_resume()
{
	__call_aul_handler(AUL_RESUME, NULL);
	return 0;
}

static int app_terminate()
{
	__call_aul_handler(AUL_TERMINATE, NULL);
	return 0;
}

static int bgapp_terminate()
{
	__call_aul_handler(AUL_TERMINATE_BGAPP, NULL);
	return 0;
}

static int app_pause()
{
	__call_aul_handler(AUL_PAUSE, NULL);
	return 0;
}

static int app_prepare_to_suspend()
{
	_D("[__SUSPEND__]");
	__call_aul_handler(AUL_SUSPEND, NULL);
	return 0;
}

static int app_prepare_to_wake()
{
	_D("[__WAKE__]");
	__call_aul_handler(AUL_WAKE, NULL);
	return 0;
}

/**
 * @brief	encode kb and send it to 'pid'
 * @param[in]	pid		receiver's pid
 * @param[in]	cmd		message's status (APP_START | APP_RESULT)
 * @param[in]	kb		data
 */
SLPAPI int app_send_cmd(int pid, int cmd, bundle *kb)
{
	int datalen;
	bundle_raw *kb_data = NULL;
	int res = AUL_R_OK;

	res = bundle_encode(kb, &kb_data, &datalen);
	if (res != BUNDLE_ERROR_NONE) {
		return AUL_R_EINVAL;
	}
	if ((res = __app_send_raw(pid, cmd, kb_data, datalen)) < 0) {
		switch (res) {
		case -EINVAL:
			res = AUL_R_EINVAL;
			break;
		case -ECOMM:
			res = AUL_R_ECOMM;
			break;
		case -EAGAIN:
			res = AUL_R_ETIMEOUT;
			break;
		case -ELOCALLAUNCH_ID:
			res = AUL_R_LOCAL;
			break;
		case -EILLEGALACCESS:
			res = AUL_R_EILLACC;
			break;
		case -ETERMINATING:
			res = AUL_R_ETERMINATING;
			break;
		case -ENOLAUNCHPAD:
			res = AUL_R_ENOLAUNCHPAD;
			break;
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
		case -EUGLOCAL_LAUNCH:
			res = AUL_R_UG_LOCAL;
			break;
#endif
		case -EREJECTED:
			res = AUL_R_EREJECTED;
			break;
		case -ENOAPP:
			res = AUL_R_ENOAPP;
			break;
		default:
			res = AUL_R_ERROR;
		}
	}
	free(kb_data);

	return res;
}

SLPAPI int app_send_cmd_with_noreply(int pid, int cmd, bundle *kb)
{
	int datalen;
	bundle_raw *kb_data = NULL;
	int res = AUL_R_OK;

	res = bundle_encode(kb, &kb_data, &datalen);
	if (res != BUNDLE_ERROR_NONE) {
		return AUL_R_EINVAL;
	}
	if ((res = __app_send_raw_with_noreply(pid, cmd, kb_data, datalen)) < 0) {
		switch (res) {
		case -EINVAL:
			res = AUL_R_EINVAL;
			break;
		case -ECOMM:
			res = AUL_R_ECOMM;
			break;
		case -EAGAIN:
			res = AUL_R_ETIMEOUT;
			break;
		case -ELOCALLAUNCH_ID:
			res = AUL_R_LOCAL;
			break;
		case -EILLEGALACCESS:
			res = AUL_R_EILLACC;
			break;
		default:
			res = AUL_R_ERROR;
		}
	}
	free(kb_data);

	return res;
}

static void __clear_internal_key(bundle *kb)
{
	bundle_del(kb, AUL_K_CALLER_PID);
	bundle_del(kb, AUL_K_PKG_NAME);
	bundle_del(kb, AUL_K_WAIT_RESULT);
	bundle_del(kb, AUL_K_SEND_RESULT);
	bundle_del(kb, AUL_K_ARGV0);
}

static inline void __set_stime(bundle *kb)
{
	struct timeval tv;
	char tmp[MAX_LOCAL_BUFSZ];

	gettimeofday(&tv, NULL);
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%ld/%ld", tv.tv_sec, tv.tv_usec);
	bundle_add(kb, AUL_K_STARTTIME, tmp);
}

static int __app_start_internal(gpointer data)
{
	bundle *kb;

	kb = (bundle *) data;
	app_start(kb);
	bundle_free(kb);

	return 0;
}

static int __app_launch_local(bundle *b)
{
	if (!aul_is_initialized())
		return AUL_R_ENOINIT;

	if (b == NULL) {
		_E("bundle for APP_START is NULL");
	}
	if (g_idle_add(__app_start_internal, b) > 0)
		return AUL_R_OK;
	else
		return AUL_R_ERROR;
}

static int __app_resume_local()
{
	if (!aul_is_initialized())
		return AUL_R_ENOINIT;

	app_resume();

	return 0;
}

static int __app_pause_local()
{
	if (!aul_is_initialized())
		return AUL_R_ENOINIT;

	app_pause();

	return 0;
}

/**
 * @brief	start caller with kb
 * @return	callee's pid
 */
int app_request_to_launchpad(int cmd, const char *pkgname, bundle *kb)
{
	int must_free = 0;
	int ret = 0;

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	char oldZone[64] = { 0, };
	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
#endif

	traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "AUL:REQ_TO_PAD");
	SECURE_LOGD("launch request : %s", pkgname);
	if (kb == NULL) {
		kb = bundle_create();
		if (kb == NULL)
			return AUL_R_ERROR;
		must_free = 1;
	} else {
		__clear_internal_key(kb);
	}

	ret = bundle_add(kb, AUL_K_PKG_NAME, pkgname);
	if (ret != BUNDLE_ERROR_NONE) {
		if (must_free)
			bundle_free(kb);
		return AUL_R_ERROR;
	}
	__set_stime(kb);

	switch (cmd) {
	case APP_START_ASYNC:
	case APP_PAUSE:
	case APP_PAUSE_BY_PID:
		ret = app_send_cmd_with_noreply(AUL_UTIL_PID, cmd, kb);
		break;
	default:
		ret = app_send_cmd(AUL_UTIL_PID, cmd, kb);
		break;
	}

	_D("launch request result : %d", ret);
	if (ret == AUL_R_LOCAL
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
		|| ret == AUL_R_UG_LOCAL
#endif
		) {
		_E("app_request_to_launchpad : Same Process Send Local");
		bundle *b = NULL;

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
		if(ret == AUL_R_UG_LOCAL) {
			pkgmgrinfo_appinfo_h handle;
			char *exec = NULL;

			pkgmgrinfo_appinfo_get_appinfo(pkgname, &handle);
			pkgmgrinfo_appinfo_get_exec(handle, &exec);

			bundle_add(kb, "__AUL_UG_EXEC__", exec);

			pkgmgrinfo_appinfo_destroy_appinfo(handle);
		}
#endif

		switch (cmd) {
			case APP_START:
			case APP_START_RES:
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
			case APP_START_MULTI_INSTANCE:
#endif
				b = bundle_dup(kb);
				ret = __app_launch_local(b);
				break;
			case APP_OPEN:
			case APP_RESUME:
			case APP_RESUME_BY_PID:
				ret = __app_resume_local();
				break;
			case APP_PAUSE:
			case APP_PAUSE_BY_PID:
				ret = __app_pause_local();
				break;
			default:
				_E("no support packet");
		}

	}

	/* cleanup */
	if (must_free)
		bundle_free(kb);

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
#endif

	traceEnd(TTRACE_TAG_APPLICATION_MANAGER);

	return ret;
}

static int __send_result_to_launchpad(int fd, int res)
{
	if (send(fd, &res, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
			close(fd);
			return -1;
		}
		_E("send fail to client");
	}
	close(fd);
	return 0;
}

/**
 * @brief	caller & callee's sock handler
 */
int aul_sock_handler(int fd)
{
	app_pkt_t *pkt;
	bundle *kbundle;
	int clifd;
	struct ucred cr;

	const char *str = NULL;
	int pid;
	int ret;

	if ((pkt = __app_recv_raw(fd, &clifd, &cr)) == NULL) {
		_E("recv error");
		return -1;
	}

	if (pkt->cmd != APP_RESULT && pkt->cmd != APP_CANCEL && pkt->cmd != APP_SUSPEND && pkt->cmd != APP_WAKE
		&&cr.uid != 0 && cr.uid != SYSTEM_UID) {
		_E("security error");
		__send_result_to_launchpad(clifd, -1);
		free(pkt);
		return -1;
	}

	if (pkt->cmd != APP_RESULT && pkt->cmd != APP_CANCEL && pkt->cmd != APP_KEY_EVENT && pkt->cmd != APP_TERM_BY_PID_ASYNC
		&& pkt->cmd != APP_SUSPEND && pkt->cmd != APP_WAKE ) {
		ret = __send_result_to_launchpad(clifd, 0);
		if (ret < 0) {
			free(pkt);
			return -1;
		}
	} else {
		close(clifd);
	}

	switch (pkt->cmd) {
	case APP_START:	/* run in callee */
	case APP_START_RES:
	case APP_START_ASYNC:
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	case APP_START_MULTI_INSTANCE:
#endif
		kbundle = bundle_decode(pkt->data, pkt->len);
		if (kbundle == NULL)
			goto err;
		app_start(kbundle);
		bundle_free(kbundle);
		break;

	case APP_OPEN:	/* run in callee */
	case APP_RESUME:
	case APP_RESUME_BY_PID:
		app_resume();
		break;

	case APP_SUSPEND:
		app_prepare_to_suspend();
		break;
	case APP_WAKE:
		app_prepare_to_wake();
		break;
	case APP_TERM_BY_PID:	/* run in callee */
	case APP_TERM_BY_PID_ASYNC:
		app_terminate();
		break;

	case APP_TERM_BGAPP_BY_PID:
		bgapp_terminate();
		break;

	case APP_TERM_REQ_BY_PID:	/* run in callee */
		app_subapp_terminate_request();
		break;

	case APP_RESULT:	/* run in caller */
	case APP_CANCEL:
		kbundle = bundle_decode(pkt->data, pkt->len);
		if (kbundle == NULL)
			goto err;

		str = bundle_get_val(kbundle, AUL_K_CALLEE_PID);
		if(str) {
			pid = atoi(str);
			app_result(pkt->cmd, kbundle, pid);
		}
		bundle_free(kbundle);
		break;

	case APP_KEY_EVENT:	/* run in caller */
		kbundle = bundle_decode(pkt->data, pkt->len);
		if (kbundle == NULL)
			goto err;
		app_key_event(kbundle);
		bundle_free(kbundle);
		break;

	case APP_PAUSE_BY_PID:
		app_pause();
		break;

	default:
		_E("no support packet");
	}

	free(pkt);
	return 0;

err:
	free(pkt);
	return -1;
}

int aul_make_bundle_from_argv(int argc, char **argv, bundle **kb)
{
	int ac = 1;

	char *buf = NULL;

	*kb = bundle_create();
	if (*kb == NULL)
		return AUL_R_ERROR;

	if (argv == NULL)
		return AUL_R_OK;

	if ((argv != NULL) && (argv[0] != NULL)) {
		buf = strdup(argv[0]);
		if (NULL == buf) {
			_E("Malloc failed");
			return AUL_R_ERROR;
		}

		bundle_add(*kb, AUL_K_ARGV0, buf);
	}
	if (buf) {		/*Prevent FIX: ID 38717 */
		free(buf);
		buf = NULL;
	}

	while (ac < argc) {
		if (ac + 1 == argc) {
			if (bundle_add(*kb, argv[ac], "") < 0) {
				_E("bundle add error pos - %d", ac);
				return AUL_R_ECANCELED;
			}
		} else {
			if (bundle_add(*kb, argv[ac], argv[ac + 1]) < 0) {
				_E("bundle add error pos - %d", ac);
				return AUL_R_ECANCELED;
			}
		}
		ac = ac + 2;
	}

	return AUL_R_OK;
}

int aul_register_init_callback(
	int (*aul_handler) (aul_type type, bundle *, void *), void *data)
{
	/* Save start handler function in static var */
	_aul_handler = aul_handler;
	_aul_data = data;
	return 0;
}

int aul_initialize()
{
	if (aul_initialized) {
		_E("aul already initialized");
		return AUL_R_ECANCELED;
	}
	aul_fd = __create_server_sock(getpid() + _pid_offset);
	if (aul_fd < 0) {
		_E("aul_init create sock failed");
		return AUL_R_ECOMM;
	}
	aul_initialized = 1;

	return aul_fd;
}

SLPAPI void aul_finalize()
{

	aul_launch_fini();

	if (aul_initialized) {
		close(aul_fd);
		aul_initialized = 0;
	}

	return;
}


SLPAPI int aul_launch_app(const char *appid, bundle *kb)
{
	if (appid == NULL)
		return AUL_R_EINVAL;

	return app_request_to_launchpad(APP_START, appid, kb);
}

SLPAPI int aul_launch_app_async(const char *appid, bundle *kb)
{
	if (appid == NULL)
		return AUL_R_EINVAL;

	return app_request_to_launchpad(APP_START_ASYNC, appid, kb);
}

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
SLPAPI int aul_launch_app_for_multi_instance(const char *appid, bundle *kb)
{
	if (appid == NULL)
		return AUL_R_EINVAL;

	return app_request_to_launchpad(APP_START_MULTI_INSTANCE, appid, kb);
}
#endif

SLPAPI int aul_open_app(const char *appid)
{
	if (appid == NULL)
		return AUL_R_EINVAL;

	return app_request_to_launchpad(APP_OPEN, appid, NULL);
}

SLPAPI int aul_resume_app(const char *appid)
{
	if (appid == NULL)
		return AUL_R_EINVAL;

	return app_request_to_launchpad(APP_RESUME, appid, NULL);
}

SLPAPI int aul_resume_pid(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_RESUME_BY_PID, pkgname, NULL);
	return ret;
}

SLPAPI int aul_terminate_pid(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BY_PID, pkgname, NULL);
	return ret;
}

SLPAPI int aul_terminate_bgapp_pid(int pid)
{
        char pkgname[MAX_PID_STR_BUFSZ];
        int ret;

        if (pid <= 0)
                return AUL_R_EINVAL;

        snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
        ret = app_request_to_launchpad(APP_TERM_BGAPP_BY_PID, pkgname, NULL);
        return ret;
}

SLPAPI int aul_terminate_pid_without_restart(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BY_PID_WITHOUT_RESTART, pkgname, NULL);
	return ret;
}

SLPAPI int aul_terminate_pid_async(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BY_PID_ASYNC, pkgname, NULL);
	return ret;
}

SLPAPI int aul_kill_pid(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_KILL_BY_PID, pkgname, NULL);
	return ret;
}

#ifdef _APPFW_FEATURE_PROCESS_POOL
SLPAPI void aul_set_preinit_window(void *evas_object)
{
        __window_object = evas_object;
}

SLPAPI void* aul_get_preinit_window(const char *win_name)
{
        return __window_object;
}

SLPAPI void aul_set_preinit_background(void *evas_object)
{
        __bg_object = evas_object;
}

SLPAPI void* aul_get_preinit_background(void)
{
        return __bg_object;
}

SLPAPI void aul_set_preinit_conformant(void *evas_object)
{
	__conformant_object = evas_object;
}

SLPAPI void* aul_get_preinit_conformant(void)
{
	return __conformant_object;
}
#endif

#ifdef _APPFW_FEATURE_DATA_CONTROL
SLPAPI int aul_set_data_control_provider_cb(data_control_provider_handler_fn handler)
{
	__dc_handler = handler;
	return 0;
}

SLPAPI int aul_unset_data_control_provider_cb(void)
{
	__dc_handler = NULL;
	return 0;
}
#endif

SLPAPI int aul_pause_app(const char *appid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad(APP_PAUSE, appid, NULL);
	return ret;
}

SLPAPI int aul_pause_pid(int pid)
{
	char app_pid[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(app_pid, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_PAUSE_BY_PID, app_pid, NULL);
	return ret;
}

/* vi: set ts=8 sts=8 sw=8: */
