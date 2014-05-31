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


#include "aul.h"
#include "aul_api.h"
#include "mida.h"
#include "miregex.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xdgmime.h>
#include <bundle.h>
#include <errno.h>

#include "menu_db_util.h"
#include "simple_util.h"

#ifdef WEARABLE_PROFILE
#define MIME_APP_SELECTOR "com.samsung.app-selector"
#else
#define MIME_APP_SELECTOR "org.tizen.app-selector"
#endif

static int __match_content_with_regex(const char *content, regex_t *regex_preg);
static int get_defapp_from_desktop(const char *mimetype, char *defapp, int len);
static int _aul_get_defapp_from_mime(const char *mimetype, char *unaliased,
				     char *defapp, int len_unaliased,
				     int len_defapp);
static int __launch_with_defapp(const char *mime_type, 
					const char *mime_content);



static int __match_content_with_regex(const char *content, regex_t *regex_preg)
{
	if (regexec(regex_preg, content, 0, NULL, 0) == 0)
		return 1;
	else
		return 0;
}

SLPAPI int aul_get_mime_from_content(const char *content, char *mimetype,
				     int len)
{
	char *founded = NULL;
	regex_tbl *miregex_tbl = NULL;

	if (content == NULL)
		return AUL_R_EINVAL;

	if ((miregex_tbl = miregex_get_regex_table()) == NULL) {
		_E("load miregex_table fail\n");
		return AUL_R_ERROR;
	}

	while (miregex_tbl) {
		if (__match_content_with_regex(content,
			&(miregex_tbl->regex_preg))) {
			founded = miregex_tbl->mimetype;
			SECURE_LOGD("content %s => mimetype %s\n", content, founded);
			break;
		}
		miregex_tbl = miregex_tbl->next;
	}

	if (founded != NULL)
		snprintf(mimetype, len, "%s", founded);
	else {
		/* TODO : should to try to extract from share mime info's data*/
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

SLPAPI int aul_get_mime_description(const char *mimetype, char *desc, int len)
{
	regex_tbl *miregex_tbl = NULL;
	char *founded = NULL;

	if (mimetype == NULL)
		return AUL_R_EINVAL;

	if ((miregex_tbl = miregex_get_regex_table()) == NULL) {
		_E("load miregex_table fail\n");
		return AUL_R_ERROR;
	}

	while (miregex_tbl) {
		if (strcmp(miregex_tbl->mimetype, mimetype) == 0) {
			founded = miregex_tbl->desc;
			_D("mimetype %s => desc %s\n", mimetype, founded);
			break;
		}
		miregex_tbl = miregex_tbl->next;
	}

	if (founded != NULL)
		snprintf(desc, len, "%s", founded);
	else {
		/* TODO : should to try to extract from 
		   share mime info's comment */
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

SLPAPI int aul_get_mime_extension(const char *mimetype, char *ext, int len)
{
	const char **extlist;
	int totlen = 0;
	const char *unaliased_mimetype;

	if (mimetype == NULL || ext == NULL || len <= 0)
		return AUL_R_EINVAL;

	unaliased_mimetype = xdg_mime_unalias_mime_type(mimetype);
	if (unaliased_mimetype == NULL)
		return AUL_R_ERROR;

	extlist = xdg_mime_get_file_names_from_mime_type(unaliased_mimetype);
	if (extlist == NULL)
		return AUL_R_ERROR;

	if (extlist[0] == NULL)
		return AUL_R_ERROR;

	ext[0] = 0;
	while (*extlist != NULL) {
		if (*(extlist + 1) == NULL) {
			snprintf(&ext[totlen], len - totlen, "%s", *extlist);
			break;
		} else {
			snprintf(&ext[totlen], len - totlen, "%s,", *extlist);
			if (strlen(*extlist) > len - totlen - 1)
				break;
			totlen += strlen(*extlist) + 1;
			extlist++;
		}
	}

	return AUL_R_OK;
}

SLPAPI int aul_get_mime_icon(const char *mimetype, char *iconname, int len)
{
	const char *icon;
	const char *unaliased_mimetype;

	if (mimetype == NULL || iconname == NULL || len <= 0)
		return AUL_R_EINVAL;

	unaliased_mimetype = xdg_mime_unalias_mime_type(mimetype);
	if (unaliased_mimetype == NULL)
		return AUL_R_ERROR;

	icon = xdg_mime_get_icon(unaliased_mimetype);
	if (icon == NULL)
		icon = xdg_mime_get_generic_icon(unaliased_mimetype);

	if (icon != NULL) {
		snprintf(iconname, len, "%s", icon);
		return AUL_R_OK;
	} else
		return AUL_R_ERROR;
}

SLPAPI int aul_get_mime_from_file(const char *filename, char *mimetype, int len)
{
	const char *mime;
	struct stat 	statbuf;
	if (filename == NULL)
		return AUL_R_EINVAL;

	if (access(filename, F_OK) != 0) {
		_E("access fail(%s)", strerror(errno));
		return AUL_R_EINVAL;
	}

	if (stat(filename, &statbuf) != 0){
		_E("Unable to get stat, error is %s", strerror(errno));
		return AUL_R_ERROR;
	}
	if(S_ISDIR(statbuf.st_mode))
		return AUL_R_EINVAL;

	mime = xdg_mime_get_mime_type_for_file(filename, 0);
	if (strcmp(mime, "application/octet-stream") == 0) {
		mime = xdg_mime_get_mime_type_from_file_name(filename);
	}

	snprintf(mimetype, len, "%s", mime);
	return AUL_R_OK;
}

SLPAPI int aul_set_defapp_with_mime(const char *mimetype, const char *defapp)
{
	const char *unaliased_mimetype;

	if (mimetype == NULL || defapp == NULL) {
		_E("invalid arg");
		return AUL_R_EINVAL;
	}

	unaliased_mimetype = xdg_mime_unalias_mime_type(mimetype);
	if (unaliased_mimetype == NULL)
		return AUL_R_ERROR;

	if (mida_add_app(unaliased_mimetype, defapp) < 0) {
		_E("fail to add: mimtype-%s and defapp-%s", unaliased_mimetype,
		   defapp);
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

static ail_cb_ret_e __defapp_with_mime_func(
			const ail_appinfo_h appinfo, void *user_data)
{
	char **package = (char **)user_data;
	char *str;

	ail_appinfo_get_str(appinfo, AIL_PROP_PACKAGE_STR, &str);

	_D("defapp from desktop = %s", str);

	*package = strdup(str);
	
	return AIL_CB_RET_CANCEL;	/*return AIL_CB_RET_CONTINUE;*/	
}

static int get_defapp_from_desktop(const char *mimetype, char *defapp, int len)
{
	ail_filter_h filter;
	ail_error_e ret;
	int pkg_count = 0;
	char *tmp = NULL;

	ret = ail_filter_new(&filter);
	if (ret != AIL_ERROR_OK) 
		return -1;
	
	ret = ail_filter_add_str(filter, AIL_PROP_MIMETYPE_STR, mimetype);
	if (ret != AIL_ERROR_OK) {
		ret = -1;
		goto out;
	}
	
	ret = ail_filter_count_appinfo(filter, &pkg_count);
	if (ret != AIL_ERROR_OK) {
		ret = -1;
		goto out;
	}

	if (pkg_count == 1) {
		ail_filter_list_appinfo_foreach(filter, 
			__defapp_with_mime_func, (void *)&tmp);

		if(tmp) {
			strncpy(defapp,tmp,len);
			_D("defapp from desktop = %s", defapp);
			aul_set_defapp_with_mime(mimetype, defapp);
			ret = 0;
			free(tmp);
		}
	} else 
		ret = -1;
	
out:
       ail_filter_destroy(filter);
       return ret;	
}

SLPAPI int aul_get_defapp_from_mime(const char *mimetype, char *defapp, int len)
{
	char *res;
	const char *unaliased_mimetype;

	if (mimetype == NULL || defapp == NULL || len <= 0)
		return AUL_R_EINVAL;

	unaliased_mimetype = xdg_mime_unalias_mime_type(mimetype);
	if (unaliased_mimetype == NULL)
		return AUL_R_ERROR;

	/* search mida db*/
	if ((res = mida_get_app(unaliased_mimetype)) != NULL) {
		snprintf(defapp, len, "%s", res);
		free(res);
		_D("Found %s for %s from mime db", defapp, unaliased_mimetype);
		return AUL_R_OK;
	}

	if (get_defapp_from_desktop(unaliased_mimetype, defapp, len) != 0)
		return AUL_R_ERROR;
	else
		return AUL_R_OK;
}

static int _aul_get_defapp_from_mime(const char *mimetype, char *unaliased,
				     char *defapp, int len_unaliased,
				     int len_defapp)
{
	char *res;
	const char *unaliased_mimetype;

	if (mimetype == NULL || unaliased == NULL || len_unaliased <= 0
	    || defapp == NULL || len_defapp <= 0)
		return AUL_R_EINVAL;

	unaliased_mimetype = xdg_mime_unalias_mime_type(mimetype);
	if (unaliased_mimetype == NULL)
		return AUL_R_ERROR;

	snprintf(unaliased, len_unaliased, "%s", unaliased_mimetype);

	/* search mida db*/
	if ((res = mida_get_app(unaliased_mimetype)) != NULL) {
		snprintf(defapp, len_defapp, "%s", res);
		free(res);
		_D("Found %s for %s from mime db", defapp, unaliased_mimetype);
		return AUL_R_OK;
	}

	if (get_defapp_from_desktop(unaliased_mimetype, defapp, len_defapp) < 0)
		return AUL_R_ERROR;
	else
		return AUL_R_OK;
}

static int __launch_with_defapp(const char *mime_type, const char *mime_content)
{
	ail_appinfo_h handle;
	ail_error_e ail_ret;
	char defapp[MAX_LOCAL_BUFSZ];
	char unaliased_mime_type[MAX_LOCAL_BUFSZ];
	bundle *kb = NULL;
	int ret = AUL_R_ERROR;

	kb = bundle_create();
	if (NULL == kb) {
		_E("bundle creation fail");
		return ret;
	}
	bundle_add(kb, AUL_K_MIME_TYPE, mime_type);
	bundle_add(kb, AUL_K_MIME_CONTENT, mime_content);

 retry:
	if (_aul_get_defapp_from_mime
	    (mime_type, unaliased_mime_type, defapp,
	     sizeof(unaliased_mime_type), sizeof(defapp)) < 0) {
		SECURE_LOGD("mimetype : %s, unaliased mimetype : %s, mime_content : %s,"
			" no default app", mime_type, 
				unaliased_mime_type, mime_content);
		bundle_add(kb, AUL_K_UNALIASED_MIME_TYPE, unaliased_mime_type);
		ret = aul_launch_app(MIME_APP_SELECTOR, kb);
		/* TODO: When launching MIME APP SELECTOR, what should 
		be the return value? */
		/* Currently, it returns 0 if the app selector is launched */
		if (ret > 0)
			ret = 0;
	} else {
		ail_ret = ail_get_appinfo(defapp, &handle);

		if (ail_ret == AIL_ERROR_OK) {
			ail_destroy_appinfo(handle);
			SECURE_LOGD("mimetype : %s, unaliased mimetype : %s, "
				"mime_content : %s, defapp : %s", mime_type, 
					unaliased_mime_type, 
						mime_content, defapp);
			bundle_add(kb, AUL_K_UNALIASED_MIME_TYPE,
				   unaliased_mime_type);
			ret = aul_launch_app(defapp, kb);
		} else if (ail_ret == AIL_ERROR_NO_DATA) {
			SECURE_LOGD("defapp %s for mimetype : %s, mime_content : %s "
				"does NOT exist", defapp, 
					mime_type, mime_content);
			mida_delete_with_pkgname(defapp);
			ail_destroy_appinfo(handle);
			goto retry;
		} else {
			SECURE_LOGE("ail_get_appinfo with %s failed", defapp);
			if (kb) {
				bundle_free(kb);
				kb = NULL;
			}
			return ret;
		}	
	}
	bundle_free(kb);
	return ret;
}

SLPAPI int aul_open_content(const char *content)
{
	int ret;
	char mime[MAX_LOCAL_BUFSZ];
	if ((ret = aul_get_mime_from_content(content, mime, sizeof(mime))) < 0)
		return ret;

	return __launch_with_defapp(mime, content);
}

SLPAPI int aul_open_file_with_mimetype(const char *filename,
				       const char *mimetype)
{
	if (mimetype == NULL)
		return AUL_R_EINVAL;

	return __launch_with_defapp(mimetype, filename);
}

SLPAPI int aul_open_file(const char *filename)
{
	int ret;
	char mime[MAX_LOCAL_BUFSZ];
	if ((ret = aul_get_mime_from_file(filename, mime, sizeof(mime))) < 0)
		return ret;

	return __launch_with_defapp(mime, filename);
}

