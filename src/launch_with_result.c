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
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "aul.h"
#include "aul_api.h"
#include "app_sock.h"
#include "simple_util.h"
#include "launch.h"
#include "aul_util.h"

/*#define ACTIVATE_PREEMPT_FEATURE*/

typedef struct _app_resultcb_info_t {
	int launched_pid;
	void (*cb_func) (bundle *kb, int is_cancel, void *data);
	void *priv_data;
	void (*caller_cb) (int launched_pid, void *data);
	void *caller_data;
	struct _app_resultcb_info_t *next;
} app_resultcb_info_t;

static int latest_caller_pid = -1;
static app_resultcb_info_t *rescb_head = NULL;
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
static app_resultcb_info_t *rescb_head2 = NULL;
#endif


static int is_subapp = 0;
subapp_fn subapp_cb = NULL;
void *subapp_data = NULL;

pthread_mutex_t result_lock = PTHREAD_MUTEX_INITIALIZER;

static void __add_resultcb(int pid, void (*cbfunc) (bundle *, int, void *),
			 void *data);
static app_resultcb_info_t *__find_resultcb(int pid);
static void __remove_resultcb(app_resultcb_info_t *info);
static int __call_app_result_callback(bundle *kb, int is_cancel,
				    int launched_pid);
static int __get_caller_pid(bundle *kb);



static void __add_resultcb(int pid, void (*cbfunc) (bundle *, int, void *),
			 void *data)
{
	app_resultcb_info_t *info;

	info = (app_resultcb_info_t *) malloc(sizeof(app_resultcb_info_t));
	if(info == NULL)
		return;
	info->launched_pid = pid;
	info->cb_func = cbfunc;
	info->priv_data = data;
	info->caller_cb = NULL;
	info->caller_data = NULL;

	info->next = rescb_head;
	rescb_head = info;
}

static app_resultcb_info_t *__find_resultcb(int pid)
{
	app_resultcb_info_t *tmp;
	app_resultcb_info_t *ret = NULL;

	pthread_mutex_lock(&result_lock);
	tmp = rescb_head;
	while (tmp) {
		if (tmp->launched_pid == pid) {
			ret = tmp;
		}
		tmp = tmp->next;
	}
	pthread_mutex_unlock(&result_lock);

	return ret;
}

static void __remove_resultcb(app_resultcb_info_t *info)
{
	app_resultcb_info_t *tmp;

	if (rescb_head == NULL || info == NULL)
		return;

	if (rescb_head == info) {
		rescb_head = info->next;
		free(info);
		return;
	}

	tmp = rescb_head;
	while (tmp) {
		if (tmp->next == info) {
			tmp->next = info->next;
			free(info);
			return;
		}
		tmp = tmp->next;
	}
}

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
static void __add_resultcb2(int pid, void (*cbfunc) (bundle *, int, void *),
			 void *data)
{
	app_resultcb_info_t *info;

	_D("id : %d", pid);

	info = (app_resultcb_info_t *) malloc(sizeof(app_resultcb_info_t));
	if(info == NULL)
		return;
	info->launched_pid = pid;
	info->cb_func = cbfunc;
	info->priv_data = data;
	info->caller_cb = NULL;
	info->caller_data = NULL;

	info->next = rescb_head2;
	rescb_head2 = info;
}

static app_resultcb_info_t *__find_resultcb2(int pid)
{
	app_resultcb_info_t *tmp;
	app_resultcb_info_t *ret = NULL;

	pthread_mutex_lock(&result_lock);
	tmp = rescb_head2;
	while (tmp) {
		_D("id_id : %d", tmp->launched_pid);
		if (tmp->launched_pid == pid) {
			ret = tmp;
		}
		tmp = tmp->next;
	}
	pthread_mutex_unlock(&result_lock);

	return ret;
}

static void __remove_resultcb2(app_resultcb_info_t *info)
{
	app_resultcb_info_t *tmp;

	if (rescb_head2 == NULL || info == NULL)
		return;

	if (rescb_head2 == info) {
		rescb_head2 = info->next;
		free(info);
		return;
	}

	tmp = rescb_head2;
	while (tmp) {
		if (tmp->next == info) {
			tmp->next = info->next;
			free(info);
			return;
		}
		tmp = tmp->next;
	}
}
#endif

/**
 * call result callback function
 * run in caller
 */
static int __call_app_result_callback(bundle *kb, int is_cancel,
				    int launched_pid)
{
	app_resultcb_info_t *info;
	int pgid;
	char *fwdpid_str;

	if (((info = __find_resultcb(launched_pid)) == NULL)
	    || (launched_pid < 0)) {
		_E("reject by pid - wait pid = %d, recvd pid = %d\n", getpid(),
		   launched_pid);

		/* second chance - support app launched by shell script*/
		pgid = getpgid(launched_pid);
		if (pgid <= 1)
			return -1;
		if ((info = __find_resultcb(pgid)) == NULL) {
			_E("second chance : also reject pgid - %d\n", pgid);
			return -1;
		}
	}

	if (info->cb_func == NULL || kb == NULL)
		return -1;

	/* In case of aul_forward_app, update the callback data */
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	if(is_cancel == 1 && (fwdpid_str = (char *)bundle_get_val(kb, "__AUL_FWD_UG_ID__")))
	{
		app_resultcb_info_t newinfo;
		newinfo.launched_pid = atoi(fwdpid_str);
		newinfo.cb_func = info->cb_func;
		newinfo.priv_data = info->priv_data;
		newinfo.caller_cb = NULL;
		newinfo.caller_data = NULL;

		if(info->caller_cb) {
			info->caller_cb(newinfo.launched_pid, info->caller_data);
		}

		__remove_resultcb(info);
		__add_resultcb2(newinfo.launched_pid, newinfo.cb_func, newinfo.priv_data);

		_D("change callback __AUL_FWD_UG_ID__ - %d\n", newinfo.launched_pid);

		goto end;
	}
	else if(is_cancel == 1 && (fwdpid_str = (char *)bundle_get_val(kb, AUL_K_FWD_CALLEE_PID)))
#else
	if(is_cancel == 1 && (fwdpid_str = (char *)bundle_get_val(kb, AUL_K_FWD_CALLEE_PID)))
#endif
	{
		app_resultcb_info_t newinfo;
		newinfo.launched_pid = atoi(fwdpid_str);
		newinfo.cb_func = info->cb_func;
		newinfo.priv_data = info->priv_data;
		newinfo.caller_cb = NULL;
		newinfo.caller_data = NULL;

		if(info->caller_cb) {
			info->caller_cb(newinfo.launched_pid, info->caller_data);
		}

		__remove_resultcb(info);
		__add_resultcb(newinfo.launched_pid, newinfo.cb_func, newinfo.priv_data);

		_D("change callback - %s\n",AUL_K_FWD_CALLEE_PID);

		goto end;
	}

	info->cb_func(kb, is_cancel, info->priv_data);
	__remove_resultcb(info);

end:
	return 0;
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if(pid_str)
		goto end;

	pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (pid_str == NULL)
		return -1;

end:
	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
}

#ifdef ACTIVATE_PREEMPT_FEATURE
static int __send_to_cancel(int pid)
{
	/* Say "Your result request is cancel!" to caller */
	bundle *kb;
	int ret;
	char tmp_pid[MAX_PID_STR_BUFSZ];

	kb = bundle_create();
	if (kb == NULL)
		return AUL_R_ERROR;
	bundle_add(kb, AUL_K_SEND_RESULT, "1");

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", pid);
	bundle_add(kb, AUL_K_CALLER_PID, tmp_pid);

	ret = app_send_cmd(LAUNCHPAD_PID, APP_CANCEL, kb);

	bundle_free(kb);
	return ret;
}
#else
static int __send_to_cancel(int pid)
{
	return 0;
}
#endif

int _app_start_res_prepare(bundle *kb)
{
	int pid;
	const char* str = NULL;

	if (bundle_get_val(kb, AUL_K_WAIT_RESULT) == NULL)
		return 0;

	str = bundle_get_val(kb, AUL_K_NO_CANCEL);
	if( str && strncmp("1", str, 1) == 0) {
		_D("no cancel");
		return 0;
	}

	if ((pid = __get_caller_pid(kb)) < 0) {
		_E("caller pid is not valid");
		return -1;
	}
	/* If previous caller is still waiting result,
	   send cancel packet to the caller. */
	if (latest_caller_pid != -1)
		__send_to_cancel(latest_caller_pid);

	latest_caller_pid = pid;
	_D("result msg prepare done");

	return 0;
}

int app_result(int cmd, bundle *kb, int launched_pid)
{
	switch (cmd) {
	case APP_RESULT:
		__call_app_result_callback(kb, 0, launched_pid);
		break;
	case APP_CANCEL:
		__call_app_result_callback(kb, 1, launched_pid);
		break;
	}

	return 0;
}

SLPAPI int aul_launch_app_with_result(const char *pkgname, bundle *kb,
			       void (*cbfunc) (bundle *, int, void *),
			       void *data)
{
	int ret;
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	int id = -1;
	char id_str[256] = {0, };
#endif

	if (!aul_is_initialized()) {
		if (aul_launch_init(NULL, NULL) < 0)
			return AUL_R_ENOINIT;
	}

	if (pkgname == NULL || cbfunc == NULL || kb == NULL)
		return AUL_R_EINVAL;

	pthread_mutex_lock(&result_lock);
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	id = rand();
	sprintf(id_str, "%d", id);
	bundle_add(kb, "__AUL_UG_ID__", id_str);
#endif
	ret = app_request_to_launchpad(APP_START_RES, pkgname, kb);
	if (ret > 0)
		__add_resultcb(ret, cbfunc, data);
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	else if (ret == AUL_R_UG_LOCAL) {
		__add_resultcb2(id, cbfunc, data);
		pthread_mutex_unlock(&result_lock);
		return getpid();
	}
#endif
	pthread_mutex_unlock(&result_lock);

	return ret;
}

void __iterate(const char *key, const char *val, void *data)
{
	static int i=0;
	_D("%d %s %s", i++, key, val);
}

SLPAPI int aul_forward_app(const char* pkgname, bundle *kb)
{
	char *caller;
	int ret;
	bundle *dupb;
	bundle *outb;
	char tmp_pid[MAX_PID_STR_BUFSZ];
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	int caller_pid;
	int callee_pid;
#endif

	if(pkgname == NULL || kb == NULL)
		return AUL_R_EINVAL;

	caller = (char *)bundle_get_val(kb, AUL_K_CALLER_PID);
	if(caller == NULL) {
		_E("original msg doest not have caller pid");
		return AUL_R_EINVAL;
	}

	bundle_del(kb, AUL_K_ORG_CALLER_PID);
	bundle_add(kb, AUL_K_ORG_CALLER_PID, caller);

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	caller_pid = atoi(caller);
#endif

	dupb = bundle_dup(kb);
	if(dupb == NULL) {
		_E("bundle duplicate fail");
		return AUL_R_EINVAL;
	}

	if(bundle_get_val(kb, AUL_K_WAIT_RESULT) != NULL) {
		ret = app_request_to_launchpad(APP_START_RES, pkgname, kb);
		if(ret < 0)
			goto end;
	} else {
		ret = app_request_to_launchpad(APP_START, pkgname, kb);
		goto end;
	}

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	callee_pid = ret;
#endif

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ,"%d",ret);

	ret = aul_create_result_bundle(dupb, &outb);
	if(ret < 0)
		goto end;

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
	_D("callee_pid(%d) caller_pid(%d)", callee_pid, caller_pid);

	if(callee_pid == caller_pid) {
		bundle_del(outb, AUL_K_FWD_CALLEE_PID);
		bundle_add(outb, "__AUL_FWD_UG_ID__", bundle_get_val(kb, "__AUL_UG_ID__"));
	} else {
		bundle_del(outb, AUL_K_FWD_CALLEE_PID);
		bundle_add(outb, AUL_K_FWD_CALLEE_PID, tmp_pid);
	}
#else
	bundle_del(outb, AUL_K_FWD_CALLEE_PID);
	bundle_add(outb, AUL_K_FWD_CALLEE_PID, tmp_pid);
#endif

//	bundle_iterate(outb, __iterate, NULL);

	ret = aul_send_result(outb, 1);

	bundle_free(outb);
end:
	bundle_free(dupb);

	return ret;
}


SLPAPI int aul_create_result_bundle(bundle *inb, bundle **outb)
{
	const char *pid_str;

	*outb = NULL;

	if(inb == NULL){
		_E("return msg create fail");
		return AUL_R_EINVAL;
	}

	*outb = bundle_create();
	if (*outb == NULL) {
		_E("return msg create fail");
		return AUL_R_ERROR;
	}

	if(bundle_get_val(inb, AUL_K_WAIT_RESULT) != NULL) {
		bundle_add(*outb, AUL_K_SEND_RESULT, "1");
		_D("original msg is msg with result");
	} else {
		_D("original msg is not msg with result");
	}


	pid_str = bundle_get_val(inb, AUL_K_ORG_CALLER_PID);
	if(pid_str) {
		bundle_add(*outb, AUL_K_ORG_CALLER_PID, pid_str);
		goto end;
	}

	pid_str = bundle_get_val(inb, AUL_K_CALLER_PID);
	if (pid_str == NULL) {
		_E("original msg doest not have caller pid");
		bundle_free(*outb);
		*outb = NULL;
		return AUL_R_EINVAL;
	}
	bundle_add(*outb, AUL_K_CALLER_PID, pid_str);

end:
	return AUL_R_OK;
}

int aul_send_result(bundle *kb, int is_cancel)
{
	int pid;
	int ret;
	int callee_pid;
	int callee_pgid;
	char callee_appid[256];
	char tmp_pid[MAX_PID_STR_BUFSZ];

	if ((pid = __get_caller_pid(kb)) < 0)
		return AUL_R_EINVAL;

	_D("caller pid : %d", pid);

	if (bundle_get_val(kb, AUL_K_SEND_RESULT) == NULL)
	{
		_D("original msg is not msg with result");
		return AUL_R_OK;
	}

	callee_pid = getpid();
	callee_pgid = getpgid(callee_pid);
	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", callee_pgid);
	bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);

	ret = aul_app_get_appid_bypid(callee_pid, callee_appid, sizeof(callee_appid));
	if(ret == 0) {
		bundle_add(kb, AUL_K_CALLEE_APPID, callee_appid);
	} else {
		_W("fail(%d) to get callee appid by pid", ret);
	}

	ret = app_send_cmd_with_noreply(AUL_UTIL_PID, (is_cancel==1)? APP_CANCEL : APP_RESULT, kb);

	_D("app_send_cmd_with_noreply : %d", ret);

	if(latest_caller_pid == pid)
		latest_caller_pid = -1;

	return ret;
}

int app_subapp_terminate_request()
{
	if(is_subapp) {
		subapp_cb(subapp_data);

		return 0;
	}

	return -1;
}

SLPAPI int aul_set_subapp(subapp_fn cb, void *data)
{
	is_subapp = 1;
	subapp_cb = cb;
	subapp_data = data;

	return 0;
}

SLPAPI int aul_subapp_terminate_request_pid(int pid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;
	app_resultcb_info_t *info;

	if (pid <= 0)
		return AUL_R_EINVAL;

	info = __find_resultcb(pid);
	if(info)
		__remove_resultcb(info);

	snprintf(pid_str, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_REQ_BY_PID, pid_str, NULL);
	return ret;
}

SLPAPI int aul_is_subapp()
{
	return is_subapp;
}

SLPAPI int aul_add_caller_cb(int pid,  void (*caller_cb) (int, void *), void *data)
{
	app_resultcb_info_t *info;

	if (pid <= 0)
		return AUL_R_EINVAL;

	info = __find_resultcb(pid);
	if (info) {
		info->caller_cb = caller_cb;
		info->caller_data = data;
	}

	return 0;
}

SLPAPI int aul_remove_caller_cb(int pid)
{
	app_resultcb_info_t *info;

	if (pid <= 0)
		return AUL_R_EINVAL;

	info = __find_resultcb(pid);
	if(info) {
		info->caller_cb = NULL;
		info->caller_data = NULL;
	}

	return 0;
}

#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
SLPAPI int aul_call_ug_result_callback(bundle *kb, int is_cancel, int id)
{
	app_resultcb_info_t *info;
	int pgid;

	info = __find_resultcb2(id);

	_D("id : %d", id);

	info->cb_func(kb, is_cancel, info->priv_data);
	__remove_resultcb2(info);

	return 0;
}
#endif

