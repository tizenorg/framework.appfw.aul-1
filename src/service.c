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


#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <stdio.h>
#include <string.h>
#include <bundle.h>

#include "aul_service.h"
#include "aul.h"
#include "aul_api.h"
#include "mida.h"
#include "menu_db_util.h"
#include "simple_util.h"
#include "launch.h"

static int __get_defapp_from_desktop(const char *svcname, 
					char *defapp, int len);



SLPAPI int aul_set_defapp_for_service(const char *svcname, const char *defapp)
{
	if ((svcname == NULL) || (defapp == NULL))
		return AUL_R_EINVAL;

	if (!is_supported_svc(svcname))
		return AUL_R_EINVAL;

	if (svc_add_app(svcname, defapp) < 0) {
		_E("fail to add");
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

static ail_cb_ret_e __defapp_with_service_func(
			const ail_appinfo_h appinfo, void *user_data)
{
	char **package = (char **)user_data;
	char *str;

	ail_appinfo_get_str(appinfo, AIL_PROP_PACKAGE_STR, &str);

	_D("defapp from desktop = %s", str);

	*package = strdup(str);
	
	return AIL_CB_RET_CANCEL;	/*return AIL_CB_RET_CONTINUE;*/	
}


static int __get_defapp_from_desktop(const char *svcname, char *defapp, int len)
{
	char *pkgname = NULL;
	int ret = -1;
	ail_filter_h filter;
	ail_error_e ail_ret;
	int pkg_count = -1;

	_D("The svcname is: %s", svcname);

	ail_ret = ail_filter_new(&filter);
	if (ail_ret != AIL_ERROR_OK) 
		return ret;
	
	ail_ret = ail_filter_add_str(filter, AIL_PROP_X_SLP_SERVICE_STR, svcname);
	if (ail_ret != AIL_ERROR_OK) {
		_E("ail_filter_add_str failed");
		goto out;
	}

	ail_ret = ail_filter_count_appinfo(filter, &pkg_count);
	if (ail_ret != AIL_ERROR_OK) {
		_E("ail_filter_count_appinfo failed");
		goto out;
	}

	
	/* TODO: Prioritizing inhouse app depending on the UX policy */
	if (pkg_count == 1) {
		ail_filter_list_appinfo_foreach(filter, 
			__defapp_with_service_func, (void *)&pkgname);

		if(pkgname) {
			strncpy(defapp,pkgname,len);
			_D("defapp from desktop = %s", defapp);
			 aul_set_defapp_for_service(svcname, defapp);
			ret = 0;
			free(pkgname);
		}
		
	} 

 out:
	if (ail_filter_destroy(filter) != AIL_ERROR_OK)
		_E("ail_filter_destroy failed");
	return ret;
}

SLPAPI int aul_get_defapp_for_service(const char *svcname, char *defapp,
				      int len)
{
	char *res = NULL;

	if ((svcname == NULL) || (defapp == NULL) || len <= 0)
		return AUL_R_EINVAL;

	if (!is_supported_svc(svcname))
		return AUL_R_EINVAL;

	/* search mida db*/
	if ((res = svc_get_app(svcname)) != NULL) {
		snprintf(defapp, len, "%s", res);
		free(res);
		_D("Found %s for %s from svc db", defapp, svcname);
		return AUL_R_OK;
	}

	if (__get_defapp_from_desktop(svcname, defapp, len) < 0)
		return AUL_R_ERROR;
	else
		return AUL_R_OK;
}

SLPAPI int aul_open_service(const char *svcname, bundle *kb,
			    aul_service_res_fn cbfunc, void *userdata)
{
	char defapp[MAX_LOCAL_BUFSZ];
	int must_free = 0;
	int ret = AUL_R_ERROR;
	ail_appinfo_h handle;
	ail_error_e ail_ret;

	if (svcname == NULL)
		return AUL_R_EINVAL;

	if (!is_supported_svc(svcname))
		return AUL_R_EINVAL;

	if (kb == NULL) {
		kb = bundle_create();
		must_free = 1;
	}
	bundle_add(kb, AUL_K_SERVICE_NAME, svcname);

 retry:
	if (aul_get_defapp_for_service(svcname, defapp, sizeof(defapp)) < 0) {
		_D("service : %s, no default app", svcname);
		if (must_free) {
			bundle_free(kb);
			kb = NULL;
		}
		return ret;
	} else {
		ail_ret = ail_get_appinfo(defapp, &handle);

		if (ail_ret == AIL_ERROR_OK) {
			ail_destroy_appinfo(handle);
			_D("svcname: %s, defapp : %s", svcname, defapp);
			
			if (cbfunc) {
				_D("svcname: %s, defapp : %s - with result",
				   svcname, defapp);
				ret =
				    aul_launch_app_with_result(defapp, kb,
							       cbfunc,
							       userdata);
			} else {
				_D("svcname: %s, defapp : %s - no result",
				   svcname, defapp);
				ret = aul_launch_app(defapp, kb);
			}
		} else if (ail_ret == AIL_ERROR_NO_DATA) {
			_D("defapp %s for svcname: %s does NOT exist", defapp,
			   svcname);
			svc_delete_with_pkgname(defapp);
			ail_destroy_appinfo(handle);
			goto retry;
		} else {
			_E("ail_get_appinfo with %s failed", defapp);
			if (must_free) {
				bundle_free(kb);
				kb = NULL;
			}
			return ret;
		}	
	}
	if (must_free)
		bundle_free(kb);

	return ret;

}

SLPAPI int aul_send_service_result(bundle *b)
{
	return aul_send_result(b, 0);
}

