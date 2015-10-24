/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <glib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <Ecore_X.h>
#include <Ecore.h>
#include <iniparser.h>
#include <pkgmgr-info.h>
#include <pkgmgrinfo_zone.h>
#include "aul.h"
#include "aul_api.h"
#include "aul_svc.h"
#include "aul_svc_db.h"
#include "simple_util.h"
#include "aul_svc_priv_key.h"
#include "aul_zone.h"
#include "delegator_client.h"
#include "launch.h"

/* callback handling */
typedef struct _aul_svc_cb_info_t {
	aul_svc_res_fn cb_func;
	int request_code;
	void *data;
} aul_svc_cb_info_t;

typedef struct _aul_svc_resolve_info_t {
	char *pkgname;
	char *op;
	char *uri;
	char *scheme;
	char *host;
	char *uri_r_info;
	char *origin_mime;
	char *mime;
	char *m_type;
	char *s_type;
	char *category;
	char *win_id;
	int mime_set;
} aul_svc_resolve_info_t;

typedef struct _aul_svc_transient_cb_info_t {
	aul_svc_host_res_fn cb_func;
	Ecore_X_Window win_id;
	void *data;
} aul_svc_transient_cb_info_t;

pthread_mutex_t iniparser_lock = PTHREAD_MUTEX_INITIALIZER;
GSList *tmp_list;

static aul_svc_cb_info_t *__create_rescb(int request_code,
        aul_svc_res_fn cbfunc,
        void *data);
static void __remove_rescb(aul_svc_cb_info_t *info);
static int __set_bundle(bundle *b, const char *key, const char *value);
static void __aul_cb(bundle *b, int is_cancel, void *data);
static int __run_svc_with_pkgname(char *pkgname, bundle *b, int request_code,
                                  aul_svc_res_fn cbfunc, void *data);
static int __get_resolve_info(bundle *b, aul_svc_resolve_info_t *info);
static int __free_resolve_info_data(aul_svc_resolve_info_t *info);

static void __set_transient_for(Ecore_X_Window callee, Ecore_X_Window caller,
                                void *data);

static char *white_list[] = {
	APP_SELECTOR,
	SHARE_PANEL,
	NULL
};

static bool __is_special_app(const char *appid)
{
	const char *id;
	int i = 0;

	if (appid == NULL)
		return false;

	while ((id = white_list[i]) != NULL) {
		if (strcmp(id, appid) == 0)
			return true;
		i++;
	}
	return false;
}

static Eina_Bool __transient_cb(void *data, int type, void *event)
{
	Ecore_X_Event_Window_Hide *ev;
	aul_svc_transient_cb_info_t*  cb_info;

	if ((!event) || (!data)) {
		_E("input param of transient cb is null");
		return ECORE_CALLBACK_CANCEL;
	}

	ev = event;
	cb_info = (aul_svc_transient_cb_info_t*) data;

	if (ev->win == cb_info->win_id) {
		if (cb_info->cb_func)
			cb_info->cb_func(cb_info->data);
		ecore_main_loop_quit();
	}

	return ECORE_CALLBACK_RENEW;
}

static int __aul_subapp_cb(void *data)
{
	aul_svc_transient_cb_info_t*  cb_info;

	cb_info = (aul_svc_transient_cb_info_t*) data;

	cb_info->cb_func(cb_info->data);
	ecore_main_loop_quit();

	return 0;
}

static aul_svc_cb_info_t *__create_rescb(int request_code,
        aul_svc_res_fn cbfunc,
        void *data)
{
	aul_svc_cb_info_t* info;

	info = (aul_svc_cb_info_t*)calloc(1, sizeof(aul_svc_cb_info_t));
	if (info == NULL)
		return NULL;

	info->request_code = request_code;
	info->cb_func = cbfunc;
	info->data = data;

	return info;
}

static void __remove_rescb(aul_svc_cb_info_t *info)
{
	if (info) free(info);
}

static int __set_bundle(bundle *b, const char *key, const char *value)
{
	const char *val = NULL;

	val = bundle_get_val(b, key);
	if (val) {
		if ( bundle_del(b, key) != 0 ) {
			return AUL_SVC_RET_ERROR;
		}
	}

	if (!value)
		return AUL_SVC_RET_EINVAL;

	if ( bundle_add(b, key, value) != 0 ) {
		return AUL_SVC_RET_ERROR;
	}

	_D("__set_bundle");

	return AUL_SVC_RET_OK;
}

static int __set_bundle_array(bundle *b, const char *key, const char **value,
                              int len)
{

	int type;
	type = aul_svc_data_is_array(b, key);

	if (type == 1) {
		if ( bundle_del(b, key) != 0 ) {
			return AUL_SVC_RET_ERROR;
		}
	}

	if (!value)
		return AUL_SVC_RET_EINVAL;

	if ( bundle_add_str_array(b, key, value, len) != 0 ) {
		return AUL_SVC_RET_ERROR;
	}

	_D("__set_bundle_array");

	return AUL_SVC_RET_OK;
}

static void __aul_cb(bundle *b, int is_cancel, void *data)
{
	const char *val = NULL;
	aul_svc_cb_info_t*  cb_info;
	int res;

	if (is_cancel)
		res = AUL_SVC_RES_CANCEL;
	else {
		/* get result_code from bundle */
		val = bundle_get_val(b, AUL_SVC_K_RES_VAL);
		res = (val == NULL) ? AUL_SVC_RES_NOT_OK : atoi(val);
	}

	/* remove result_code from bundle */
	bundle_del(b, AUL_SVC_K_RES_VAL);

	/* find corresponding callback */
	cb_info = (aul_svc_cb_info_t*)data;

	cb_info->cb_func(b, cb_info->request_code, (aul_svc_result_val)res,
	                 cb_info->data);
	__remove_rescb(cb_info);


	return;
}

static int __run_svc_with_pkgname(char *pkgname, bundle *b, int request_code,
                                  aul_svc_res_fn cbfunc, void *data)
{
	aul_svc_cb_info_t *cb_info = NULL;
	int ret = -1;

	if ( bundle_get_type(b, AUL_SVC_K_SELECTOR_EXTRA_LIST) != BUNDLE_TYPE_NONE ) {
		if ( !aul_svc_get_pkgname(b) ) {
			pkgname = APP_SELECTOR;
		}
	}

	if ( bundle_get_val(b, AUL_K_FORCE_LAUNCH_APP_SELECTOR) ) {
		pkgname = APP_SELECTOR;
	}

	if ( __is_special_app(pkgname)) {
		bundle_del(b, AUL_SVC_K_CAN_BE_LEADER);
		bundle_add_str(b, AUL_SVC_K_CAN_BE_LEADER, "true");
		bundle_del(b, AUL_SVC_K_REROUTE);
		bundle_add_str(b, AUL_SVC_K_REROUTE, "true");
		bundle_del(b, AUL_SVC_K_RECYCLE);
		bundle_add_str(b, AUL_SVC_K_RECYCLE, "true");

	}

	if (cbfunc) {
		SECURE_LOGD("pkg_name : %s - with result", pkgname);

		cb_info = __create_rescb(request_code, cbfunc, data);
		ret = aul_launch_app_with_result(pkgname, b, __aul_cb, cb_info);
	} else {
		SECURE_LOGD("pkg_name : %s - no result", pkgname);

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
		const char* data = bundle_get_val(b, AUL_SVC_K_MULTI_INSTANCE);
		if (data) {
			SECURE_LOGD("multi_instance value = %s", data);
		}

		if (data && strncmp(data, "TRUE", strlen("TRUE")) == 0) {
			ret = aul_launch_app_for_multi_instance(pkgname, b);
		} else {
			ret = aul_launch_app(pkgname, b);
		}
#else
		ret = aul_launch_app(pkgname, b);
#endif
	}

	if (ret < 0) {
		switch (ret) {
		case AUL_R_EILLACC:
			ret = AUL_SVC_RET_EILLACC;
			break;
		case AUL_R_EINVAL:
			ret = AUL_SVC_RET_EINVAL;
			break;
		case AUL_R_ETERMINATING:
			ret = AUL_SVC_RET_ETERMINATING;
			break;
		case AUL_R_EREJECTED:
			ret = AUL_SVC_RET_EREJECTED;
			break;
		case AUL_R_ENOAPP:
			ret = AUL_SVC_RET_ENOMATCH;
			break;
		default:
			ret = AUL_SVC_RET_ELAUNCH;
		}
	}

	return ret;
}

static int __get_resolve_info(bundle *b, aul_svc_resolve_info_t *info)
{
	char *tmp = NULL;
	char *strtok_buf = NULL;
	int ret = -1;

	info->op = (char *)aul_svc_get_operation(b);
	info->uri = (char *)aul_svc_get_uri(b);

	if ((info->uri) && (strcmp(info->uri, "") == 0)) {
		_E("Uri is empty");
		return AUL_SVC_RET_EINVAL;
	}

	info->origin_mime = info->mime = (char *)aul_svc_get_mime(b);
	info->pkgname = (char *)aul_svc_get_pkgname(b);
	info->category = (char *)aul_svc_get_category(b);
	info->win_id = (char *)bundle_get_val(b, AUL_SVC_K_WIN_ID);

	_D("getting resolve info for: operation - %s / uri - %s / mime - %s\n",
			info->op, info->uri, info->mime);

	if (info->uri) {
		if (strncmp(info->uri, "/", 1) == 0) {
			if (!info->mime) {
				info->origin_mime = info->mime = malloc(MAX_MIME_STR_SIZE);
				if (info->mime == NULL) {
					_E("out of memory");
					return AUL_SVC_RET_ERROR;
				}

				ret = aul_get_mime_from_file(info->uri, info->mime, MAX_MIME_STR_SIZE);
				info->mime_set = 1;
			}
			info->uri = NULL;
		} else if (strncmp(info->uri, "file:///", 8) == 0) {
			if (!info->mime) {
				info->origin_mime = info->mime = malloc(MAX_MIME_STR_SIZE);
				if (info->mime == NULL) {
					_E("out of memory");
					return AUL_SVC_RET_ERROR;
				}

				ret = aul_get_mime_from_file(&info->uri[7], info->mime, MAX_MIME_STR_SIZE);
				info->mime_set = 1;
			}
		} else if (strncmp(info->uri, "file:/", 6) == 0) {
			if (!info->mime) {
				info->origin_mime = info->mime = malloc(MAX_MIME_STR_SIZE);
				if (info->mime == NULL) {
					_E("out of memory");
					return AUL_SVC_RET_ERROR;
				}

				ret = aul_get_mime_from_file(&info->uri[5], info->mime, MAX_MIME_STR_SIZE);
				info->mime_set = 1;
			}
		}

		if (info->mime_set == 1 && ret < 0) {
			_E("aul_get_mime_from_file : %d", ret);
			free(info->mime);
			info->origin_mime = info->mime = NULL;
			info->mime_set = 0;
		}
	}

	if (info->uri) {
		GRegex *regex;
		GMatchInfo *match_info;
		GError *error = NULL;

		regex = g_regex_new ("^(([^:/?#]+):)?(//([^/?#]*))?", 0, 0, &error);
		if (g_regex_match (regex, info->uri, 0, &match_info) == FALSE) {
			g_regex_unref (regex);
			return AUL_SVC_RET_EINVAL;
		}

		info->scheme = g_match_info_fetch (match_info, 2);
		info->host = g_match_info_fetch (match_info, 4);

		if (info->scheme && info->host) {
			info->uri_r_info = malloc(MAX_SCHEME_STR_SIZE + MAX_HOST_STR_SIZE + 2);
			if (info->uri_r_info == NULL) {
				_E("out of memory");
				g_match_info_free(match_info);
				g_regex_unref(regex);
				return AUL_SVC_RET_ERROR;
			}

			snprintf(info->uri_r_info, MAX_SCHEME_STR_SIZE + MAX_HOST_STR_SIZE + 1,
			         "%s://%s", info->scheme, info->host);
		}

		g_match_info_free (match_info);
		g_regex_unref (regex);

	} else {
		info->scheme = strdup("NULL");
	}

	if (!info->mime)
		info->mime = strdup("NULL");
	else {
		info->m_type = malloc(MAX_LOCAL_BUFSZ);
		if (info->m_type == NULL) {
			_E("ouf of memory");
			return AUL_SVC_RET_ERROR;
		}

		info->s_type = malloc(MAX_LOCAL_BUFSZ);
		if (info->s_type == NULL) {
			_E("out of memory");
			free(info->m_type);
			return AUL_SVC_RET_ERROR;
		}

		tmp = strdup(info->mime);
		strtok_buf = strtok(tmp, "/");
		if (strtok_buf)
			strncpy(info->m_type, strtok_buf, MAX_LOCAL_BUFSZ - 1);
		strtok_buf = strtok(NULL, "/");
		if (strtok_buf)
			strncpy(info->s_type, strtok_buf, MAX_LOCAL_BUFSZ - 1);
		free(tmp);

		if (strncmp(info->m_type, "*", 1) == 0) {
			strncpy(info->m_type, "%", MAX_LOCAL_BUFSZ - 1);
		}
		if (strncmp(info->s_type, "*", 1) == 0) {
			strncpy(info->s_type, "%", MAX_LOCAL_BUFSZ - 1);
		}

		info->mime = malloc(MAX_MIME_STR_SIZE);
		if (info->mime == NULL) {
			_E("out of memory");
			free(info->s_type);
			free(info->m_type);
			return AUL_SVC_RET_ERROR;
		}

		snprintf(info->mime, MAX_MIME_STR_SIZE - 1, "%s/%s", info->m_type,
		         info->s_type);
	}

	return 0;
}

static int __free_resolve_info_data(aul_svc_resolve_info_t *info)
{
	if (info->mime)
		free(info->mime);
	if (info->scheme)
		free(info->scheme);
	if (info->host)
		free(info->host);
	if (info->m_type)
		free(info->m_type);
	if (info->s_type)
		free(info->s_type);
	if (info->uri_r_info)
		free(info->uri_r_info);
	if (info->mime_set)
		free(info->origin_mime);

	return 0;
}

static void __set_transient_for(Ecore_X_Window callee, Ecore_X_Window caller,
                                void *data)
{
	void (*ecore_x_icccm_transient_for_set) (Ecore_X_Window, Ecore_X_Window);
	void (*ecore_x_window_client_manage) (Ecore_X_Window);
	int* ecore_x_event_window_destroy;

	void *handle = dlopen("libecore_x.so.1", RTLD_LAZY | RTLD_LOCAL);
	if (!handle) {
		_E("dlopen error %s", dlerror());
		return;
	}

	ecore_x_icccm_transient_for_set = dlsym(handle,
	                                        "ecore_x_icccm_transient_for_set");
	if (ecore_x_icccm_transient_for_set == NULL)  {
		_E("dlsym error");
		dlclose(handle);
		return;
	}

	ecore_x_icccm_transient_for_set(callee, caller);

	ecore_x_window_client_manage = dlsym(handle, "ecore_x_window_client_manage");
	if (ecore_x_window_client_manage == NULL)  {
		_E("dlsym error");
		dlclose(handle);
		return;
	}

	ecore_x_window_client_manage(caller);

	ecore_x_event_window_destroy = dlsym(handle, "ECORE_X_EVENT_WINDOW_DESTROY");
	if (ecore_x_event_window_destroy == NULL)  {
		_E("dlsym error");
		dlclose(handle);
		return;
	}

	ecore_event_handler_add(*ecore_x_event_window_destroy, __transient_cb, data);;

	dlclose(handle);
}

static char* __get_alias_appid(char *appid)
{
	char *alias_id = NULL;
	char *val = NULL;
	char key_string[MAX_PACKAGE_STR_SIZE + 5];
	dictionary *dic;

	dic = iniparser_load("/usr/share/appsvc/alias.ini");

	if (dic == NULL)
		return NULL;

	snprintf(key_string, sizeof(key_string), "Alias:%s", appid);
	pthread_mutex_lock(&iniparser_lock);
	val = iniparser_getstr(dic, key_string);
	pthread_mutex_unlock(&iniparser_lock);

	SECURE_LOGD("alias_id : %s", val);

	if (val != NULL) {
		alias_id = malloc(MAX_PACKAGE_STR_SIZE);
		if (alias_id == NULL) {
			_E("out of memory");
			iniparser_freedict(dic);
			return NULL;
		}

		strncpy(alias_id, val, MAX_PACKAGE_STR_SIZE - 1);
	}

	iniparser_freedict(dic);

	return alias_id;
}

static int __get_list_with_condition_mime_extened(char *op, char *uri,
        char *mime, char *m_type, char *s_type, GSList **pkg_list)
{
	char *tmp;

	tmp = malloc(MAX_MIME_STR_SIZE);
	if (tmp == NULL) {
		_E("out of memory");
		return -1;
	}

	_svc_db_get_list_with_condition(op, uri, mime, pkg_list);
	if ((strncmp(mime, "NULL", 4) != 0) && (strncmp(s_type, "%", 1) != 0)) {
		snprintf(tmp, MAX_MIME_STR_SIZE - 1, "%s/*", m_type);
		_svc_db_get_list_with_condition(op, uri, tmp, pkg_list);
	}
	if ((strncmp(mime, "NULL", 4) != 0) && (strncmp(m_type, "%", 1) != 0)) {
		snprintf(tmp, MAX_MIME_STR_SIZE - 1, "*/*");
		_svc_db_get_list_with_condition(op, uri, tmp, pkg_list);
	}

	free(tmp);

	return 0;
}

static int __get_list_with_condition_mime_extened_with_collation(char *op,
        char *uri, char *mime, char *m_type, char *s_type, GSList **pkg_list)
{
	char *tmp;

	tmp = malloc(MAX_MIME_STR_SIZE);
	if (tmp == NULL) {
		_E("out of memory");
		return -1;
	}

	_svc_db_get_list_with_collation(op, uri, mime, pkg_list);
	if ((strncmp(mime, "NULL", 4) != 0) && (strncmp(s_type, "%", 1) != 0)) {
		snprintf(tmp, MAX_MIME_STR_SIZE - 1, "%s/*", m_type);
		_svc_db_get_list_with_collation(op, uri, tmp, pkg_list);
	}
	if ((strncmp(mime, "NULL", 4) != 0) && (strncmp(m_type, "%", 1) != 0)) {
		snprintf(tmp, MAX_MIME_STR_SIZE - 1, "*/*");
		_svc_db_get_list_with_collation(op, uri, tmp, pkg_list);
	}

	free(tmp);

	return 0;
}


static int __app_list_cb(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	GSList **app_list = (GSList **)user_data;
	char *str = NULL;
	GSList *iter = NULL;

	pkgmgrinfo_appinfo_get_appid(handle, &str);
	_D("Matching application is %s", str);

	for (iter = tmp_list; iter != NULL; iter = g_slist_next(iter)) {
		if (strncmp(str, (char *)iter->data, MAX_PACKAGE_STR_SIZE - 1) == 0) {
			appid = strdup(str);
			*app_list = g_slist_append(*app_list, (void *)appid);
			_D("%s is added", appid);
		}
	}

	return 0;
}

static int __get_list_with_category(char *category, GSList **pkg_list)
{
	int ret;
	pkgmgrinfo_appinfo_filter_h handle;
	GSList *app_list = NULL;
	GSList *iter = NULL;
	char *list_item = NULL;

	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	ret = pkgmgrinfo_appinfo_filter_add_string(handle,
	        PMINFO_APPINFO_PROP_APP_CATEGORY, category);

	tmp_list = *pkg_list;
	ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(handle, __app_list_cb,
	        &app_list);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(handle);
		return -1;
	}
	pkgmgrinfo_appinfo_filter_destroy(handle);

	for (iter = *pkg_list; iter != NULL; iter = g_slist_next(iter)) {
		list_item = (char *)iter->data;
		g_free(list_item);
	}
	g_slist_free(*pkg_list);

	*pkg_list = app_list;

	return 0;
}

static int __appid_compare(gconstpointer data1, gconstpointer data2)
{
	char *a = (char *)data1;
	char *b = (char *)data2;
	return strcmp(a, b);
}

static int __check_mainapp_mode(char *operation)
{
	return 0;
}

static int __get_list_with_submode(char *operation, char *win_id,
                                   GSList **pkg_list)
{
	int ret = 0;
	int mainapp_mode = 0;

	mainapp_mode = __check_mainapp_mode(operation);

	SECURE_LOGD("mainapp_mode : %d", mainapp_mode);

	ret = _svc_db_adjust_list_with_submode(mainapp_mode, win_id, pkg_list);

	if (ret < 0) {
		_E("error on get_list_with_submode :%d", ret);
		return -1;
	}

	return 0;
}

SLPAPI int aul_svc_set_operation(bundle *b, const char *operation)
{
	if (b == NULL) {
		_E("bundle for aul_svc_set_operation is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_OPERATION, operation);
}

SLPAPI int aul_svc_set_uri(bundle *b, const char *uri)
{
	if (b == NULL) {
		_E("bundle for aul_svc_set_uri is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_URI, uri);
}

SLPAPI int aul_svc_set_mime(bundle *b, const char *mime)
{
	if (b == NULL) {
		_E("bundle for aul_svc_set_mime is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_MIME, mime);
}

SLPAPI int aul_svc_add_data(bundle *b, const char *key, const char *val)
{
	if (b == NULL || key == NULL) {
		return AUL_SVC_RET_EINVAL;
	}

	/* check key for data */
	/******************/

	return __set_bundle(b, key, val);
}

SLPAPI int aul_svc_add_data_array(bundle *b, const char *key,
                                  const char **val_array, int len)
{
	if (b == NULL || key == NULL) {
		return AUL_SVC_RET_EINVAL;
	}

	/* check key for data */
	/******************/

	return __set_bundle_array(b, key, val_array, len);
}


SLPAPI int aul_svc_set_pkgname(bundle *b, const char *pkg_name)
{
	if (b == NULL) {
		_E("bundle for aul_svc_set_pkgname is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_PKG_NAME, pkg_name);
}


SLPAPI int aul_svc_set_appid(bundle *b, const char *appid)
{
	char *alias_id = NULL;
	int ret;

	if (b == NULL || appid == NULL) {
		_E("bundle for aul_svc_set_appid is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	alias_id = __get_alias_appid((char *)appid);
	if (alias_id == NULL) {
		ret = __set_bundle(b, AUL_SVC_K_PKG_NAME, appid);
	} else {
		ret = __set_bundle(b, AUL_SVC_K_PKG_NAME, alias_id);
		free(alias_id);
	}

	return ret;
}

SLPAPI int aul_svc_set_category(bundle *b, const char *category)
{
	if (b == NULL) {
		_E("bundle for aul_svc_set_category is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_CATEGORY, category);
}

SLPAPI int aul_svc_set_launch_mode(bundle *b, const char *mode)
{
	if (b == NULL) {
		_E("bundle for aul_svc_set_launch_mode is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_LAUNCH_MODE, mode);
}

SLPAPI int aul_svc_run_service(bundle *b, int request_code,
                               aul_svc_res_fn cbfunc,
                               void *data)
{
	aul_svc_resolve_info_t info;
	char *pkgname;
	char *operation;
	int pkg_count = 0;
	int ret = -1;
	char oldZone[64] = { 0, };

	GSList *pkg_list = NULL;
	GSList *iter = NULL;
	char *list_item;

	if (b == NULL) {
		_E("bundle for aul_svc_set_appid is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);
	pkgname = (char *)aul_svc_get_pkgname(b);
	operation = (char *)aul_svc_get_operation(b);

	char *zone = NULL;

	if (delegator_client_can_jump(&zone, b) == AUL_SVC_RET_OK) {
		ret = delegator_client_launch(zone, b);
		if (zone != NULL)
			free(zone);
		return ret;
	}

	/* explict*/
	if (pkgname) {
		if (operation == NULL)
			aul_svc_set_operation(b, AUL_SVC_OPERATION_DEFAULT);
		ret = __run_svc_with_pkgname(pkgname, b, request_code, cbfunc, data);
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return ret;
	}

	/* share panel */
	if (operation && (strcmp(operation, AUL_SVC_OPERATION_SHARE) == 0
		|| strcmp(operation, AUL_SVC_OPERATION_MULTI_SHARE) == 0
		|| strcmp(operation, AUL_SVC_OPERATION_SHARE_TEXT) == 0)) {
		ret = __run_svc_with_pkgname(SHARE_PANEL, b, request_code, cbfunc, data);
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return ret;
	}

	memset(&info, 0, sizeof(aul_svc_resolve_info_t));
	ret = __get_resolve_info(b, &info);
	if (ret < 0) {
		__free_resolve_info_data(&info);
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return ret;
	}

	SECURE_LOGD("op - %s / mime - %s / scheme - %s\n", info.op, info.origin_mime,
	            info.scheme);

	ret = _svc_db_check_perm();
	if (ret < 0) {
		_E("permission error : %d", ret);
		ret = AUL_SVC_RET_EILLACC;
		goto end;
	}

	/*uri*/
	pkgname = _svc_db_get_app(info.op, info.origin_mime, info.uri);
	if (pkgname == NULL) {
		__get_list_with_condition_mime_extened_with_collation(info.op, info.uri,
		        info.mime, info.m_type, info.s_type, &pkg_list);
		pkg_count = g_slist_length(pkg_list);
		if (pkg_count > 0) {

			if (info.uri_r_info) {
				__get_list_with_condition_mime_extened(info.op, info.uri_r_info,
					info.mime, info.m_type, info.s_type, &pkg_list);
			}

			__get_list_with_condition_mime_extened(info.op, info.scheme,
				info.mime, info.m_type, info.s_type, &pkg_list);

			__get_list_with_condition_mime_extened(info.op, "*",
				info.mime, info.m_type, info.s_type, &pkg_list);

			if (info.scheme && (strcmp(info.scheme, "file") == 0)
				&& info.mime && (strcmp(info.mime, "NULL") != 0)) {
				__get_list_with_condition_mime_extened(info.op, "NULL",
					info.mime, info.m_type, info.s_type, &pkg_list);
			}

			if (info.category) {
				__get_list_with_category(info.category, &pkg_list);
			}

			__get_list_with_submode(info.op, info.win_id, &pkg_list);

			pkg_count = g_slist_length(pkg_list);
			_D("pkg_count : %d", pkg_count);

			if (pkg_count == 1) {
				pkgname = (char *)pkg_list->data;
				if (pkgname != NULL) {
					ret = __run_svc_with_pkgname(pkgname, b, request_code, cbfunc, data);
					goto end;
				}
			} else {
				bundle_add(b, AUL_SVC_K_URI_R_INFO, info.uri);
				ret = __run_svc_with_pkgname(APP_SELECTOR, b, request_code, cbfunc, data);
				goto end;
			}
			for (iter = pkg_list; iter != NULL; iter = g_slist_next(iter)) {
				list_item = (char *)iter->data;
				g_free(list_item);
			}
			g_slist_free(pkg_list);
			pkg_list = NULL;
		}
	} else {
		ret = __run_svc_with_pkgname(pkgname, b, request_code, cbfunc, data);
		free(pkgname);
		goto end;
	}

	/*scheme & host*/
	if (info.uri_r_info) {
		pkgname = _svc_db_get_app(info.op, info.origin_mime, info.uri_r_info);

		if (pkgname == NULL) {
			__get_list_with_condition_mime_extened(info.op, info.uri_r_info,
			                                       info.mime, info.m_type, info.s_type, &pkg_list);
			pkg_count = g_slist_length(pkg_list);
			if (pkg_count > 0) {
				__get_list_with_condition_mime_extened(info.op, info.scheme,
					info.mime, info.m_type, info.s_type, &pkg_list);

				__get_list_with_condition_mime_extened(info.op, "*",
					info.mime, info.m_type, info.s_type, &pkg_list);

				if (info.scheme && (strcmp(info.scheme, "file") == 0)
					&& info.mime && (strcmp(info.mime, "NULL") != 0)) {
					__get_list_with_condition_mime_extened(info.op, "NULL",
						info.mime, info.m_type, info.s_type, &pkg_list);
				}

				if (info.category) {
					__get_list_with_category(info.category, &pkg_list);
				}

				__get_list_with_submode(info.op, info.win_id, &pkg_list);

				pkg_count = g_slist_length(pkg_list);
				_D("pkg_count : %d", pkg_count);

				if (pkg_count == 1) {
					pkgname = (char *)pkg_list->data;
					if (pkgname != NULL) {
						ret = __run_svc_with_pkgname(pkgname, b, request_code, cbfunc, data);
						goto end;
					}
				} else {
					bundle_add(b, AUL_SVC_K_URI_R_INFO, info.uri_r_info);
					ret = __run_svc_with_pkgname(APP_SELECTOR, b, request_code, cbfunc, data);
					goto end;
				}
			}
			for (iter = pkg_list; iter != NULL; iter = g_slist_next(iter)) {
				list_item = (char *)iter->data;
				g_free(list_item);
			}
			g_slist_free(pkg_list);
			pkg_list = NULL;
		}  else {
			ret = __run_svc_with_pkgname(pkgname, b, request_code, cbfunc, data);
			free(pkgname);
			goto end;
		}
	}

	/*scheme*/
	pkgname = _svc_db_get_app(info.op, info.origin_mime, info.scheme);

	if (pkgname == NULL) {
		__get_list_with_condition_mime_extened(info.op, info.scheme,
			info.mime, info.m_type, info.s_type, &pkg_list);

		__get_list_with_condition_mime_extened(info.op, "*",
			info.mime, info.m_type, info.s_type, &pkg_list);

		if (info.scheme && (strcmp(info.scheme, "file") == 0)
			&& info.mime && (strcmp(info.mime, "NULL") != 0)) {
			__get_list_with_condition_mime_extened(info.op, "NULL",
				info.mime, info.m_type, info.s_type, &pkg_list);
		}

		if (info.category) {
			__get_list_with_category(info.category, &pkg_list);
		}

		__get_list_with_submode(info.op, info.win_id, &pkg_list);

		pkg_count = g_slist_length(pkg_list);
		_D("pkg_count : %d", pkg_count);

		if (pkg_count == 1) {
			pkgname = (char *)pkg_list->data;
			if (pkgname != NULL) {
				ret = __run_svc_with_pkgname(pkgname, b, request_code, cbfunc, data);
			}
		} else if (pkg_count < 1) {
			__free_resolve_info_data(&info);
			pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
			return AUL_SVC_RET_ENOMATCH;
		} else {
			bundle_add(b, AUL_SVC_K_URI_R_INFO, info.scheme);
			ret = __run_svc_with_pkgname(APP_SELECTOR, b, request_code, cbfunc, data);
		}

		for (iter = pkg_list; iter != NULL; iter = g_slist_next(iter)) {
			list_item = (char *)iter->data;
			g_free(list_item);
		}
		g_slist_free(pkg_list);
	} else {
		ret = __run_svc_with_pkgname(pkgname, b, request_code, cbfunc, data);
		free(pkgname);
	}

end:
	__free_resolve_info_data(&info);

	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
	return ret;
}

SLPAPI int aul_svc_get_list(bundle *b, aul_svc_info_iter_fn iter_fn, void *data)
{
	aul_svc_resolve_info_t info;
	char *pkgname = NULL;
	int pkg_count;
	int ret = -1;
	char oldZone[64] = { 0, };

	GSList *pkg_list = NULL;
	GSList *iter = NULL;

	if (b == NULL) {
		_E("bundle for aul_svc_run_service is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	if (iter_fn == NULL) {
		_E("iter_fn for aul_svc_run_service is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);

	/* parse bundle */
	memset(&info, 0, sizeof(aul_svc_resolve_info_t));
	ret = __get_resolve_info(b, &info);
	if (ret < 0) {
		__free_resolve_info_data(&info);
		return ret;
	}

	_D("operation - %s / shceme - %s / mime - %s\n", info.op, info.scheme,
	   info.mime);

	__get_list_with_condition_mime_extened_with_collation(info.op, info.uri,
	        info.mime, info.m_type, info.s_type, &pkg_list);

	if (info.uri_r_info) {
		__get_list_with_condition_mime_extened(info.op, info.uri_r_info,
			info.mime, info.m_type, info.s_type, &pkg_list);
	}

	__get_list_with_condition_mime_extened(info.op, info.scheme,
		info.mime, info.m_type, info.s_type, &pkg_list);

	__get_list_with_condition_mime_extened(info.op, "*",
		info.mime, info.m_type, info.s_type, &pkg_list);

	if (info.scheme && (strcmp(info.scheme, "file") == 0)
		&& info.mime && (strcmp(info.mime, "NULL") != 0)) {
		__get_list_with_condition_mime_extened(info.op, "NULL",
			info.mime, info.m_type, info.s_type, &pkg_list);
	}

	if (info.category) {
		__get_list_with_category(info.category, &pkg_list);
	}

	__get_list_with_submode(info.op, info.win_id, &pkg_list);

	pkg_count = g_slist_length(pkg_list);
	if (pkg_count == 0) {
		_E("Cannot find associated application");

		__free_resolve_info_data(&info);
		pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
		return AUL_SVC_RET_ENOMATCH;
	}

	for (iter = pkg_list; iter != NULL; iter = g_slist_next(iter)) {
		pkgname = iter->data;
		SECURE_LOGD("PKGNAME : %s\n", pkgname);
		if ( iter_fn(pkgname, data) != 0)
			break;
		g_free(pkgname);
	}

	g_slist_free(pkg_list);
	__free_resolve_info_data(&info);

	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
	return AUL_SVC_RET_OK;
}

SLPAPI int aul_svc_get_all_defapps(aul_svc_info_iter_fn iter_fn, void *data)
{
	char *pkgname = NULL;
	int ret = -1;
	char oldZone[64] = { 0, };

	GSList *pkg_list = NULL;
	GSList *iter = NULL;

	pkgmgrinfo_pkginfo_set_zone(_cur_zone, oldZone, 64);

	ret = _svc_db_check_perm();
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_get_list_with_all_defapps(&pkg_list);
	if (ret < 0)
		return ret;

	for (iter = pkg_list; iter != NULL; iter = g_slist_next(iter)) {
		pkgname = iter->data;
		if ( iter_fn(pkgname, data) != 0)
			break;
		g_free(pkgname);
	}

	g_slist_free(pkg_list);

	pkgmgrinfo_pkginfo_set_zone(oldZone, NULL, 0);
	return AUL_SVC_RET_OK;
}

SLPAPI const char *aul_svc_get_operation(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_OPERATION);
}

SLPAPI const char *aul_svc_get_uri(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_URI);
}

SLPAPI const char *aul_svc_get_mime(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_MIME);
}

SLPAPI const char *aul_svc_get_data(bundle *b, const char *key)
{
	return bundle_get_val(b, key);
}

SLPAPI const char **aul_svc_get_data_array(bundle *b, const char *key, int *len)
{
	return bundle_get_str_array(b, key, len);
}

SLPAPI const char *aul_svc_get_pkgname(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_PKG_NAME);
}

SLPAPI const char *aul_svc_get_appid(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_PKG_NAME);
}

SLPAPI const char *aul_svc_get_category(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_CATEGORY);
}

SLPAPI const char *aul_svc_get_launch_mode(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_LAUNCH_MODE);
}

SLPAPI int aul_svc_create_result_bundle(bundle *inb, bundle **outb)
{
	int ret = -1;

	if (inb == NULL || outb == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	ret = aul_create_result_bundle(inb, outb);

	/* add additional bundle */
	/*  bundle_add(outb, " ", " ");  */

	if (ret == AUL_R_OK)
		ret = AUL_SVC_RET_OK;
	else if (ret == AUL_R_EINVAL)
		ret = AUL_SVC_RET_EINVAL;
	else
		ret = AUL_SVC_RET_ERROR;

	return ret;
}

SLPAPI int aul_svc_send_result(bundle *b, aul_svc_result_val result)
{
	int ret;
	char tmp[MAX_LOCAL_BUFSZ];

	if (b == NULL) {
		_E("aul_svc_send_result is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	if (result != AUL_SVC_RES_OK && result != AUL_SVC_RES_NOT_OK) {
		_E("invalid result %d", (int)result);
		return AUL_SVC_RET_EINVAL;
	}

	/* add result_code to bundle */
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%d", (int)result);
	ret = __set_bundle(b, AUL_SVC_K_RES_VAL, tmp);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	ret = aul_send_service_result(b);

	/* remove result_code from bundle */
	bundle_del(b, AUL_SVC_K_RES_VAL);

	return ret;
}

SLPAPI int aul_svc_set_defapp(const char *op, const char *mime_type,
                              const char *uri,
                              const char *defapp)
{
	int ret;

	if (op == NULL || defapp == NULL)
		return AUL_SVC_RET_EINVAL;

	ret = _svc_db_check_perm();
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_add_app(op, mime_type, uri, defapp);

	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

SLPAPI int aul_svc_unset_defapp(const char *defapp)
{
	int ret;

	if (defapp == NULL)
		return AUL_SVC_RET_EINVAL;

	ret = _svc_db_check_perm();
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_delete_with_pkgname(defapp);

	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

SLPAPI int aul_svc_unset_all_defapps()
{
	int ret;

	ret = _svc_db_check_perm();
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_delete_all();

	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

SLPAPI int aul_svc_is_defapp(const char *pkg_name)
{
	int ret;

	ret = _svc_db_check_perm();
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	return _svc_db_is_defapp(pkg_name);
}

SLPAPI int aul_svc_data_is_array(bundle *b, const char *key)
{
	int type;
	type = bundle_get_type(b, key);

	if (type <= 0)
		return 0;

	if (type & BUNDLE_TYPE_ARRAY)
		return 1;
	return 0;
}

SLPAPI int aul_svc_allow_transient_app(bundle *b, int wid)
{
	char win_id[MAX_LOCAL_BUFSZ];

	snprintf(win_id, MAX_LOCAL_BUFSZ, "%d", wid);

	if (b == NULL) {
		_E("bundle for aul_svc_allow_transient_app is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_WIN_ID, win_id);
}

SLPAPI int aul_svc_request_transient_app(bundle *b, int callee_wid,
        aul_svc_host_res_fn cbfunc, void *data)
{
	const char *caller = NULL;
	Ecore_X_Window caller_wid;
	aul_svc_transient_cb_info_t* info;

	caller = bundle_get_val(b, AUL_SVC_K_WIN_ID);
	if (caller == NULL)
		return AUL_SVC_RET_ERROR;

	caller_wid = atoi(caller);

	if (callee_wid == caller_wid) {
		_E("callee window id is same as calleer window id. request will be ignored");
		return AUL_SVC_RET_EINVAL;
	}

	info = (aul_svc_transient_cb_info_t*)calloc(1,
	        sizeof(aul_svc_transient_cb_info_t));
	if (info == NULL)
		return AUL_SVC_RET_ERROR;

	info->win_id = caller_wid;
	info->cb_func = cbfunc;
	info->data = data;

	__set_transient_for(callee_wid, caller_wid, info);

	aul_set_subapp(__aul_subapp_cb, info);

	return 0;
}

SLPAPI int aul_svc_subapp_terminate_request_pid(int pid)
{
	int cpid = getpid();
	int lcnt;
	int *lpids = NULL;
	int i;

	aul_app_group_get_leader_pids(&lcnt, &lpids);
	for (i = 0; i < lcnt; i++) {
		if (lpids[i] == cpid) {
			int cnt;
			int *pids = NULL;

			aul_app_group_get_group_pids(cpid, &cnt, &pids);

			if (cnt == 0) {
				free(lpids);
				if (pids)
					free(pids);

				return aul_subapp_terminate_request_pid(pid);
			}

			if (pids != NULL)
				free(pids);
			break;
		}
	}

	if (lpids != NULL)
		free(lpids);

	return aul_app_group_clear_top();
}

SLPAPI int aul_send_service_result(bundle *b)
{
	return aul_send_result(b, 0);
}

SLPAPI int aul_svc_subscribe_launch_result(bundle *b, const char *result)
{
	if (b == NULL) {
		_E("bundle for aul_svc_subscribe_launch_result is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, result, "1");
}
