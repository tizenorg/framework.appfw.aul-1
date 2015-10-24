#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <glib.h>
#include <dirent.h>

#include <pkgmgr-info.h>
#include <vconf.h>
#include "amd_config.h"
#include "simple_util.h"
#include "amd_appinfo.h"
#include "amd_launch.h"
#include "amd_request.h"
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
#include <pkgmgr-info.h>
#include <pkgmgrinfo_type.h>
#endif


#define SERVICE_GROUP "Service"

struct appinfomgr {
	GHashTable *tbl; /* key is filename, value is struct appinfo */
};

enum _appinfo_idx {
	_AI_FILE = 0, /* service filename */
	_AI_NAME,
	_AI_EXEC,
	_AI_TYPE,
	_AI_ONBOOT,
	_AI_RESTART,
	_AI_MULTI,
	_AI_HWACC,
	_AI_PERM,
	_AI_PKGID,
	_AI_TASKMANAGE,
	_AI_PRELOAD,
	_AI_INDICATORDISP,
	_AI_EFFECTIMAGEPORT,
	_AI_EFFECTIMAGELAND,
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
	_AI_EFFECTTYPE,
#endif
	_AI_STATUS,
#ifdef _APPFW_FEATURE_PROCESS_POOL
	_AI_POOL,
#endif
	_AI_COMPTYPE,
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	_AI_MULTI_INSTANCE,
	_AI_MULTI_INSTANCE_MAINID,
	_AI_TOGGLE_ORDER,
#endif
#ifdef _APPFW_FEATURE_TTS_MODE
	_AI_TTS,
#endif
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	_AI_UPS,
#endif
#ifdef _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT
	_AI_COOLDOWN,
#endif
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	_AI_TEP,
	_AI_STORAGE_TYPE,
#endif
	_AI_ALLOWED_BG,
	_AI_API_VER,
	_AI_LAUNCH_MODE,
#ifdef _APPFW_FEATURE_EFFECTIVE_APPID
	_AI_EFFECTIVE_APPID,
#endif
#ifdef _APPFW_FEATURE_PRIVATE_SERVICE
	_AI_VISIBILITY,
#endif
	_AI_MAX,
};
#define _AI_START _AI_NAME /* start index */

struct appinfo_t {
	char *name;
	enum appinfo_type type;
};

static struct appinfo_t _appinfos[] = {
	[_AI_NAME] = { "Name", AIT_NAME, },
	[_AI_EXEC] = { "Exec", AIT_EXEC, },
	[_AI_TYPE] = { "PkgType", AIT_TYPE, },
	[_AI_ONBOOT] = { "StartOnBoot", AIT_ONBOOT, },
	[_AI_RESTART] = { "AutoRestart", AIT_RESTART, },
	[_AI_MULTI] = { "Multiple", AIT_MULTI, },
	[_AI_HWACC] = { "Hwacceleration", AIT_HWACC, },
	[_AI_PERM] = { "PermissionType", AIT_PERM, },
	[_AI_PKGID] = { "PackageId", AIT_PKGID, },
	[_AI_TASKMANAGE] = { "Taskmanage", AIT_TASKMANAGE, },
	[_AI_PRELOAD] = { "Preload", AIT_PRELOAD, },
	[_AI_INDICATORDISP] = { "indicatordisplay", AIT_INDICATOR_DISP, },
	[_AI_EFFECTIMAGEPORT] = { "portaitimg", AIT_EFFECTIMAGEPORT, },
	[_AI_EFFECTIMAGELAND] = { "landscapeimg", AIT_EFFECTIMAGELAND, },
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
	[_AI_EFFECTTYPE] = { "EffectType", AIT_EFFECTTYPE, },
#endif
	[_AI_STATUS] = { "status", AIT_STATUS, },
#ifdef _APPFW_FEATURE_PROCESS_POOL
	[_AI_POOL] = { "ProcessPool", AIT_POOL, },
#endif
	[_AI_COMPTYPE] = { "ComponentType", AIT_COMPTYPE, },
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	[_AI_MULTI_INSTANCE] = { "multi-instance", AIT_MULTI_INSTANCE, },
	[_AI_MULTI_INSTANCE_MAINID] = { "multi-instance-mainid", AIT_MULTI_INSTANCE_MAINID, },
	[_AI_TOGGLE_ORDER] = { "toggleOrder", AIT_TOGGLE_ORDER, },
#endif
#ifdef _APPFW_FEATURE_TTS_MODE
	[_AI_TTS] = { "TTS", AIT_TTS, },
#endif
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	[_AI_UPS] = { "UPS", AIT_UPS, },
#endif
#ifdef _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT
	[_AI_COOLDOWN] = { "CoolDown", AIT_COOLDOWN, },
#endif
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	[_AI_TEP] = {"Tep", AIT_TEP},
	[_AI_STORAGE_TYPE] = {"StorageType", AIT_STORAGE_TYPE},
#endif
	[_AI_ALLOWED_BG] = {"AllowedBackground", AIT_ALLOWED_BG },
	[_AI_API_VER] = {"ApiVersion", AIT_API_VER },
	[_AI_LAUNCH_MODE] = {"launch_mode", AIT_LAUNCH_MODE },
#ifdef _APPFW_FEATURE_EFFECTIVE_APPID
	[_AI_EFFECTIVE_APPID] = {"effective-appid", AIT_EFFECTIVE_APPID },
#endif
#ifdef _APPFW_FEATURE_PRIVATE_SERVICE
	[_AI_VISIBILITY] = {"visibility", AIT_VISIBILITY },
#endif

};

struct appinfo {
	char *val[_AI_MAX];
};

struct pkginfo {
	char *pkgid;
	char *op;
};

int gles = 1;

GHashTable *pkg_tbl;

static void _free_appinfo(gpointer data)
{
	struct appinfo *c = data;
	int i;

	if (!c)
		return;

	for (i = 0; i < sizeof(c->val)/sizeof(c->val[0]); i++) {
		if(c->val[i] != NULL)
			free(c->val[i]);
	}

	free(c);
}

static void _fini(struct appinfomgr *cf)
{
	assert(cf);

	g_hash_table_destroy(cf->tbl);
	g_hash_table_destroy(pkg_tbl);
	free(cf);
}

static int __set_allowed_bg(const char *category_name, void *user_data)
{
	/* assume any of background category declared means that background running is allowed */
	bool *allowed_bg = (bool *)user_data;

	if (category_name && strcmp(category_name, "enable") == 0) {
		return 0;
	}

	if (category_name && strcmp(category_name, "disable") == 0) {
		*allowed_bg = false;
		return -1;
	}

	_D("background category:%s", category_name);
	*allowed_bg = true;
	return -1;
}

static int __app_info_insert_handler(const pkgmgrinfo_appinfo_h handle, void *data)
{
	struct appinfo *c;
	struct appinfomgr *cf = (struct appinfomgr *)data;
	gboolean r;
	char *exec;
	char *portraitimg;
	char *landscapeimg;
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
	char *effectimg_type;
#endif
	char *type;
	char *appid;
	char *pkgid;
	char *component_type;
	char *multi_mainid;
	bool multiple;
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	bool multi_instance;
#endif
	bool onboot;
	bool restart;
	pkgmgrinfo_app_hwacceleration hwacc;
	pkgmgrinfo_permission_type permission;
	bool indicator_display;
	int ret = -1;
	bool taskmanage;
	bool preload;
#ifdef _APPFW_FEATURE_PROCESS_POOL
	bool process_pool = 0;
#endif
	int support_mode = 0;

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	char *tep_name = NULL;
	pkgmgrinfo_installed_storage installed_storage;
#endif
	bool allowed_bg = false;
#ifdef _APPFW_FEATURE_EFFECTIVE_APPID
	char *effective_appid = NULL;
#endif
	char *api_ver = NULL;
	char *mode = NULL;

	if (!handle) {
		_E("null app handle");
		return -1;
	}

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_E("fail to get appinfo");
		return -1;
	}

	g_hash_table_remove(cf->tbl, appid);

	c = calloc(1, sizeof(*c));
	if (!c) {
		_E("create appinfo: %s", strerror(errno));
		return -1;
	}

	memset(c, 0, sizeof(struct appinfo));

	c->val[_AI_FILE] = strdup(appid);
	if (!c->val[_AI_FILE]) {
		_E("create appinfo: %s", strerror(errno));
		_free_appinfo(c);
		return -1;
	}

	c->val[_AI_NAME] = strdup(appid);

	r = pkgmgrinfo_appinfo_is_multiple(handle, &multiple);
	if(multiple == true)
		c->val[_AI_MULTI] = strdup("true");
	else c->val[_AI_MULTI] = strdup("false");

	r = pkgmgrinfo_appinfo_is_taskmanage(handle, &taskmanage);
	if (taskmanage == false) {
		c->val[_AI_TASKMANAGE] = strdup("false");
	} else {
		c->val[_AI_TASKMANAGE] = strdup("true");
	}

	r = pkgmgrinfo_appinfo_is_preload(handle, &preload);
	if (preload == false) {
		c->val[_AI_PRELOAD] = strdup("false");
	} else {
		c->val[_AI_PRELOAD] = strdup("true");
	}

	if(gles == 0) {
		c->val[_AI_HWACC] = strdup("NOT_USE");
	} else {
		r = pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacc);
		if (r < 0){
			_E("ERROR IN FETCHING HWACCELERATION INFO\n");
			c->val[_AI_HWACC] = NULL;
		} else {
			if (hwacc == PMINFO_HWACCELERATION_ON) {
				c->val[_AI_HWACC] = strdup("USE");
			} else if (hwacc == PMINFO_HWACCELERATION_OFF) {
				c->val[_AI_HWACC] = strdup("NOT_USE");
			} else {
				c->val[_AI_HWACC] = strdup("SYS");
			}
		}
	}

	r = pkgmgrinfo_appinfo_is_indicator_display_allowed(handle, &indicator_display);
	if (r <0 ){
		_E("ERROR IN FETCHING INDICATOR DISP INFO\n");
		c->val[_AI_INDICATORDISP] = strdup("true");
	}else{
		if (indicator_display == true){
			c->val[_AI_INDICATORDISP] = strdup("true");
		}else{
			c->val[_AI_INDICATORDISP] = strdup("false");
		}
	}

	r = pkgmgrinfo_appinfo_get_effectimage(handle, &portraitimg, &landscapeimg);
	if (r < 0){
		_E("ERROR IN FETCHING EFFECT IMAGES\n");
		c->val[_AI_EFFECTIMAGEPORT] = NULL;
		c->val[_AI_EFFECTIMAGELAND] = NULL;
	}else{
		if (portraitimg)
			c->val[_AI_EFFECTIMAGEPORT] = strdup(portraitimg);
		else
			c->val[_AI_EFFECTIMAGEPORT] = NULL;
		if (landscapeimg)
			c->val[_AI_EFFECTIMAGELAND] = strdup(landscapeimg);
		else
			c->val[_AI_EFFECTIMAGELAND] = NULL;
	}
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
	r = pkgmgrinfo_appinfo_get_effectimage_type(handle, &effectimg_type);
	c->val[_AI_EFFECTTYPE] = strdup(effectimg_type);
#endif

#ifdef _APPFW_FEATURE_PROCESS_POOL
	r = pkgmgrinfo_appinfo_is_process_pool(handle, &process_pool);
	if (process_pool == false) {
		c->val[_AI_POOL] = strdup("false");
	} else {
		c->val[_AI_POOL] = strdup("true");
	}
#endif
	r = pkgmgrinfo_appinfo_get_component_type(handle, &component_type);
	c->val[_AI_COMPTYPE] = strdup(component_type);

	r = pkgmgrinfo_appinfo_is_onboot(handle, &onboot);
	if(onboot == true)
		c->val[_AI_ONBOOT] = strdup("true");
	else c->val[_AI_ONBOOT] = strdup("false");

	r = pkgmgrinfo_appinfo_is_autorestart(handle, &restart);
	if(restart == true)
		c->val[_AI_RESTART] = strdup("true");
	else c->val[_AI_RESTART] = strdup("false");

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	r = pkgmgrinfo_appinfo_is_multi_instance(handle, &multi_instance);
	if(multi_instance == true)
		c->val[_AI_MULTI_INSTANCE] = strdup("true");
	else
		c->val[_AI_MULTI_INSTANCE] = strdup("false");

	r = pkgmgrinfo_appinfo_get_multi_instance_mainid(handle, &multi_mainid);
	c->val[_AI_MULTI_INSTANCE_MAINID] = strdup(multi_mainid);

	// Toggle order
	c->val[_AI_TOGGLE_ORDER] = strdup("0");
#endif

	r = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	c->val[_AI_EXEC] = strdup(exec);

	r = pkgmgrinfo_appinfo_get_apptype(handle, &type);
	if(strncmp(type, "capp", 4) == 0 ) {
		c->val[_AI_TYPE] = strdup("rpm");
	} else if (strncmp(type, "c++app", 6) == 0 || strncmp(type, "ospapp", 6) == 0) {
		c->val[_AI_TYPE] = strdup("tpk");
	} else if (strncmp(type, "webapp", 6) == 0) {
		c->val[_AI_TYPE] = strdup("wgt");
	}

	r = pkgmgrinfo_appinfo_get_permission_type(handle, &permission);
	if (permission == PMINFO_PERMISSION_SIGNATURE) {
		c->val[_AI_PERM] = strdup("signature");
	} else if (permission == PMINFO_PERMISSION_PRIVILEGE) {
		c->val[_AI_PERM] = strdup("privilege");
	} else {
		c->val[_AI_PERM] = strdup("normal");
	}

	pkgmgrinfo_appinfo_get_support_mode(handle, &support_mode);
#ifdef _APPFW_FEATURE_TTS_MODE
	if(support_mode & PMINFO_MODE_PROP_SCREEN_READER) {
		c->val[_AI_TTS] = strdup("true");
	} else {
		c->val[_AI_TTS] = strdup("false");
	}
#endif
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	if(support_mode & PMINFO_MODE_PROP_ULTRA_POWER_SAVING) {
		c->val[_AI_UPS] = strdup("true");
	} else {
		c->val[_AI_UPS] = strdup("false");
	}
#endif
#ifdef _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT
	if(support_mode & PMINFO_SUPPORT_MODE_COOL_DOWN) {
		c->val[_AI_COOLDOWN] = strdup("true");
	} else {
		c->val[_AI_COOLDOWN] = strdup("false");
	}
#endif

	r = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	c->val[_AI_PKGID] = strdup(pkgid);

	c->val[_AI_STATUS] = strdup("installed");

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL

	ret = pkgmgrinfo_appinfo_get_tep_name(handle, &tep_name);
	if(ret == PMINFO_R_OK) {
		c->val[_AI_TEP] = strdup(tep_name);
	}

	ret = pkgmgrinfo_appinfo_get_installed_storage_location(handle, &installed_storage);
	if(ret == PMINFO_R_OK) {
		if(installed_storage == PMINFO_INTERNAL_STORAGE)
		{
			c->val[_AI_STORAGE_TYPE] = strdup("internal");
		}
		else if(installed_storage == PMINFO_EXTERNAL_STORAGE)
		{
			c->val[_AI_STORAGE_TYPE] = strdup("external");
		}
	}
#endif

#ifdef _APPFW_FEATURE_EFFECTIVE_APPID
	ret = pkgmgrinfo_appinfo_get_effective_appid(handle, &effective_appid);
	if (ret == PMINFO_R_OK) {
		if (effective_appid && strlen(effective_appid) > 0)
			c->val[_AI_EFFECTIVE_APPID] = strdup(effective_appid);
	}
#endif

	ret = pkgmgrinfo_appinfo_get_api_version(handle, &api_ver);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get api version");
		_free_appinfo(c);
		return -1;
	}

	if (api_ver)
		c->val[_AI_API_VER] = strdup(api_ver);
	else
		c->val[_AI_API_VER] = strdup("NONE");

	ret = pkgmgrinfo_appinfo_get_launch_mode(handle, &mode);
	if (ret == PMINFO_R_OK && mode)
		c->val[_AI_LAUNCH_MODE] = strdup(mode);
	else
		c->val[_AI_LAUNCH_MODE] = strdup("single");

	/* TODO each background category may have different background management policies,
	 * 	so should have real background category value than allowed_background. 	*/
	pkgmgrinfo_appinfo_foreach_background_category(handle, __set_allowed_bg, &allowed_bg);
	if (ret != PMINFO_R_OK) {
		_E("Failed to check allowed background");
	}

	if (allowed_bg) {
		SECURE_LOGD("[__SUSPEND__] allowed background, appid: %s", appid);
		c->val[_AI_ALLOWED_BG] = strdup("ALLOWED_BG");
	} else {
		c->val[_AI_ALLOWED_BG] = strdup("NONE");
	}
#ifdef _APPFW_FEATURE_PRIVATE_SERVICE
	c->val[_AI_VISIBILITY] = NULL;
#endif
	SECURE_LOGD("appinfo file:%s, type:%s", c->val[_AI_FILE], c->val[_AI_TYPE]);

	g_hash_table_insert(cf->tbl, c->val[_AI_FILE], c);

	return 0;
}

static int __app_info_delete_handler(const pkgmgrinfo_appinfo_h handle, void *data)
{
	struct appinfomgr *cf = (struct appinfomgr *)data;
	char *appid = NULL;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);

	if (appid)
		g_hash_table_remove(cf->tbl, appid);

	return 0;
}

static int _read_pkg_info(struct appinfomgr *cf)
{
	int ret;

	ret = pkgmgrinfo_appinfo_get_install_list(__app_info_insert_handler, cf);
	assert(ret == PMINFO_R_OK);

	return ret;
}

static struct appinfomgr *_init()
{
	struct appinfomgr *cf;

	cf = calloc(1, sizeof(*cf));
	if (!cf) {
		_E("appinfo init: %s", strerror(errno));
		return NULL;
	}

	cf->tbl = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, _free_appinfo);

	pkg_tbl = g_hash_table_new(g_str_hash, g_str_equal);
	_E("pkg_tbl : %x", pkg_tbl);
	return cf;
}

static void __amd_pkgmgrinfo_start_handler (gpointer key, gpointer value, gpointer user_data)
{
	struct appinfo *c = value;
	char *pkgid = (char *)user_data;

	if (c != NULL && strcmp(c->val[_AI_PKGID], pkgid) == 0) {
		free(c->val[_AI_STATUS]);
		c->val[_AI_STATUS] = strdup("blocking");
		SECURE_LOGD("pkgmgr working for this application(%s)", c->val[_AI_NAME]);
	}
}

static void __amd_pkgmgrinfo_fail_handler (gpointer key, gpointer value, gpointer user_data)
{
	struct appinfo *c = value;
	char *pkgid = (char *)user_data;

	if (c != NULL && strcmp(c->val[_AI_PKGID], pkgid) == 0) {
		free(c->val[_AI_STATUS]);
		c->val[_AI_STATUS] = strdup("installed");
		SECURE_LOGD("pkgmgr fail(%s)", c->val[_AI_NAME]);
	}
}

static int __amd_pkgmgrinfo_install_end_handler(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	struct appinfomgr *cf = (struct appinfomgr *)user_data;
	struct appinfo *c;
	const char *componet;
	int r;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);

	__app_info_insert_handler(handle, user_data);
	c = g_hash_table_lookup(cf->tbl, appid);

	componet = appinfo_get_value(c, AIT_COMPTYPE);
	r = appinfo_get_boolean(c, AIT_ONBOOT);

	if (r == 1 && componet && strncmp(componet, "svcapp", 6) == 0)
	{
		SECURE_LOGW("start service - %s", appid);
		_start_srv(c);
	}

	return 0;
}

static int __amd_pkgmgrinfo_update_end_handler(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	struct appinfomgr *cf = (struct appinfomgr *)user_data;
	struct appinfo *c;
	const char *componet;
	int r;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);
	c = g_hash_table_lookup(cf->tbl, appid);

	if (c != NULL && strncmp(c->val[_AI_STATUS], "restart", 7) == 0) {
		__app_info_insert_handler(handle, user_data);
		_release_srv(appid);
	} else {
		__app_info_insert_handler(handle, user_data);
		c = g_hash_table_lookup(cf->tbl, appid);

		componet = appinfo_get_value(c, AIT_COMPTYPE);
		r = appinfo_get_boolean(c, AIT_ONBOOT);

		if (r == 1 && componet && strncmp(componet, "svcapp", 6) == 0)
		{
			SECURE_LOGW("start service - %s", appid);
			_start_srv(c);
		}
	}

	return 0;
}

static gboolean __amd_pkgmgrinfo_uninstall_end_handler (gpointer key, gpointer value, gpointer user_data)
{
	struct appinfo *c = value;
	char *pkgid = (char *)user_data;

	if (strcmp(c->val[_AI_PKGID], pkgid) == 0) {
		SECURE_LOGD("appid(%s), pkgid(%s)", c->val[_AI_NAME], pkgid);
		return TRUE;
	}
	return FALSE;
}

static int __amd_pkgmgrinfo_status_cb(int req_id, const char *pkg_type,
		       const char *pkgid, const char *key, const char *val,
		       const void *pmsg, void *user_data)
{
	int ret = 0;
	pkgmgrinfo_pkginfo_h handle;
	char *op = NULL;
	struct pkginfo *p = NULL;
	struct appinfomgr *cf = (struct appinfomgr *)user_data;

	SECURE_LOGD("pkgid(%s), key(%s), value(%s)", pkgid, key, val);

	if(strncmp(key,"start", 5) == 0) {
		g_hash_table_remove(pkg_tbl, pkgid);
		p = calloc(1, sizeof(*p));
		if (p == NULL) {
			_E("out of memory");
			return -1;
		}

		p->pkgid = strdup(pkgid);
		p->op = strdup(val);
		g_hash_table_insert(pkg_tbl, p->pkgid, p);
		if (strncmp(val, "install", 7) == 0) {

		}
		else if ((strncmp(val, "update", 6) == 0) || (strncmp(val, "uninstall", 9) == 0)) {
			g_hash_table_foreach(cf->tbl, __amd_pkgmgrinfo_start_handler, (gpointer)pkgid);
			_D("__amd_pkgmgrinfo_start_handler");
			ret = 0;
		}
	}
	else if (strncmp(key,"end", 3) == 0) {
		p = g_hash_table_lookup(pkg_tbl, pkgid);
		if(p) {
			op = p->op;
			SECURE_LOGW("op(%s), value(%s)", op, val);
			if (strncmp(val, "ok", 2) == 0) {
				if (op && strncmp(op, "install", 7)== 0) {
					ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
					if (ret != PMINFO_R_OK)
						return -1;
					ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __amd_pkgmgrinfo_install_end_handler, user_data);
					if (ret != PMINFO_R_OK) {
						pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
						return -1;
					}
					pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
				}
				else if (op && strncmp(op, "update", 6) == 0){
					ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
					if (ret != PMINFO_R_OK)
						return -1;
					ret = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __amd_pkgmgrinfo_update_end_handler, user_data);
					if (ret != PMINFO_R_OK) {
						pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
						return -1;
					}
					pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
				}
				else if (op && strncmp(op, "uninstall", 9) == 0) {
					ret = g_hash_table_foreach_remove(cf->tbl, __amd_pkgmgrinfo_uninstall_end_handler, (gpointer)pkgid);
					_D("g_hash_table_foreach_remove, %d", ret);
					ret = 0;
				}
			}
			else if (strncmp(val, "fail", 4) == 0) {
				if ((op && strncmp(op, "update", 6) == 0) || (op && strncmp(op, "uninstall", 9) ==  0) ) {
					g_hash_table_foreach(cf->tbl, __amd_pkgmgrinfo_fail_handler, (gpointer)pkgid);
					_D("__amd_pkgmgrinfo_fail_handler");
					ret = 0;
				}
			}
			g_hash_table_remove(pkg_tbl, p->pkgid);
			free(p->pkgid);
			free(p->op);
			free(p);
		}
	}
	return ret;
}

static int __unmounted_list_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	struct appinfomgr *cf = (struct appinfomgr *)user_data;
	struct appinfo *c = NULL;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (appid) {
		c = g_hash_table_lookup(cf->tbl, appid);
		SECURE_LOGD("%s : %s", c->val[_AI_FILE], c->val[_AI_STATUS]);
		free(c->val[_AI_STATUS]);
		c->val[_AI_STATUS] = strdup("unmounted");
		SECURE_LOGD("unmounted(%s)", appid);
	} else {
		_E("pkgmgrinfo_appinfo_get_appid() failed");
	}

	return 0;
}

static int __mounted_list_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	struct appinfomgr *cf = (struct appinfomgr *)user_data;
	struct appinfo *c = NULL;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (appid) {
		c = g_hash_table_lookup(cf->tbl, appid);
		SECURE_LOGD("%s : %s", c->val[_AI_FILE], c->val[_AI_STATUS]);
		if(strncmp(c->val[_AI_STATUS], "unmounted", 9) ==0 ) {
			free(c->val[_AI_STATUS]);
			c->val[_AI_STATUS] = strdup("installed");
		}
		SECURE_LOGD("mounted(%s)", appid);
	} else {
		_E("pkgmgrinfo_appinfo_get_appid() failed");
	}

	return 0;
}

#ifdef _APPFW_FEATURE_MMC_SUPPORT
static void __amd_mmc_vconf_cb(keynode_t *key, void *data)
{
	int status;
	int ret = 0;

	status = vconf_keynode_get_int(key);
	if( status < 0 ) {
		return;
	}

	if(status == VCONFKEY_SYSMAN_MMC_REMOVED || status == VCONFKEY_SYSMAN_MMC_INSERTED_NOT_MOUNTED) {
		ret = pkgmgrinfo_appinfo_get_unmounted_list(__unmounted_list_cb, data);
		if (ret != PMINFO_R_OK){
			_E("pkgmgrinfo_appinfo_get_unmounted_list failed: %d", ret);
		}
	} else if(status == VCONFKEY_SYSMAN_MMC_MOUNTED){
		ret = pkgmgrinfo_appinfo_get_mounted_list(__mounted_list_cb, data);
		if (ret != PMINFO_R_OK){
			_E("pkgmgrinfo_appinfo_get_mounted_list failed: %d", ret);
		}
	}
}
#endif

int appinfo_init(struct appinfomgr **cf)
{
	struct appinfomgr *_cf;
	int r;
	char *cmdline;
	FILE *fp = NULL;
	char buf[4096] = {0,};
	char *tmp = NULL;

	if (!cf) {
		errno = EINVAL;
		_E("appinfo init: %s", strerror(errno));
		return -1;
	}

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL){
		_E("appinfo init failed: %s", strerror(errno));
		return -1;
	}
	cmdline = fgets(buf, sizeof(buf), fp);
	if (cmdline != NULL) {
		tmp = strstr(buf, "gles");
		if(tmp != NULL) {
			sscanf(tmp,"gles=%d", &gles);
		}
	}
	fclose(fp);

	_cf = _init();
	if (!_cf) {
		assert(_cf);
		return -1;
	}

	r = _read_pkg_info(_cf);
	if (r != PMINFO_R_OK) {
		_fini(_cf);
		return -1;
	}

#ifdef _APPFW_FEATURE_MMC_SUPPORT
	r = vconf_notify_key_changed(VCONFKEY_SYSMAN_MMC_STATUS, __amd_mmc_vconf_cb, _cf);
	if (r < 0)
		_E("Unable to register vconf notification callback for VCONFKEY_SYSMAN_MMC_STATUS\n");
#endif

	int event_type = PMINFO_CLIENT_STATUS_UPGRADE | PMINFO_CLIENT_STATUS_UNINSTALL | PMINFO_CLIENT_STATUS_INSTALL;
	pkgmgrinfo_client *pc = NULL;
	pc = pkgmgrinfo_client_new(PMINFO_LISTENING);
	pkgmgrinfo_client_set_status_type(pc, event_type);
	pkgmgrinfo_client_listen_status(pc, __amd_pkgmgrinfo_status_cb , _cf);

	*cf = _cf;

	return 0;
}

void appinfo_fini(struct appinfomgr **cf)
{
	if (!cf || !*cf)
		return;

	_fini(*cf);
	*cf = NULL;
}

const struct appinfomgr *appinfo_insert(struct appinfomgr *cf, const char *pkg_name)
{
	pkgmgrinfo_pkginfo_h handle;
	if (pkgmgrinfo_pkginfo_get_pkginfo(pkg_name, &handle) == PMINFO_R_OK){
		pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __app_info_insert_handler, cf);
		pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __app_info_insert_handler, cf);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}
	return cf;
}

void appinfo_delete(struct appinfomgr *cf, const char *pkg_name)
{
	pkgmgrinfo_pkginfo_h handle;
	if (pkgmgrinfo_pkginfo_get_pkginfo(pkg_name, &handle) != PMINFO_R_OK)
		return;
	pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __app_info_delete_handler, cf);
	pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __app_info_delete_handler, cf);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
}

const struct appinfo *appinfo_find(struct appinfomgr *cf, const char *filename)
{
	if (!cf || !filename || !*filename) {
		errno = EINVAL;
		return NULL;
	}

	return g_hash_table_lookup(cf->tbl, FILENAME(filename));
}

const char *appinfo_get_value(const struct appinfo *c, enum appinfo_type type)
{
	enum _appinfo_idx i;

	if (!c) {
		errno = EINVAL;
		_E("appinfo get value: %s, %d", strerror(errno), type);
		return NULL;
	}

	for (i = _AI_START; i < sizeof(_appinfos)/sizeof(_appinfos[0]); i++) {
		if (type == _appinfos[i].type)
			return c->val[i];
	}

	errno = ENOENT;
	_E("appinfo get value: %s", strerror(errno));

	return NULL;
}

const char *appinfo_set_value(struct appinfo *c, enum appinfo_type type, const char* val)
{
	enum _appinfo_idx i;
	if (!c) {
		SECURE_LOGE("appinfo is NULL, type: %d, val: %s", type, val);
		return NULL;
	}
	for (i = _AI_START; i < sizeof(_appinfos)/sizeof(_appinfos[0]); i++) {
		if (type == _appinfos[i].type) {
			SECURE_LOGD("%s : %s : %s", c->val[_AI_FILE], c->val[i], val);
			free(c->val[i]);
			c->val[i] = strdup(val);
		}
	}

	return NULL;
}

const char *appinfo_get_filename(const struct appinfo *c)
{
	if (!c) {
		errno = EINVAL;
		SECURE_LOGE("appinfo get filename: %s", strerror(errno));
		return NULL;
	}

	return c->val[_AI_FILE];
}

struct _cbinfo {
	appinfo_iter_callback cb;
	void *cb_data;
};

static void _iter_cb(gpointer key, gpointer value, gpointer user_data)
{
	struct _cbinfo *cbi = user_data;

	assert(cbi);

	cbi->cb(cbi->cb_data, key, value);
}

void appinfo_foreach(struct appinfomgr *cf, appinfo_iter_callback cb, void *user_data)
{
	struct _cbinfo cbi;

	if (!cf || !cb) {
		errno = EINVAL;
		_E("appinfo foreach: %s", strerror(errno));
		return;
	}

	cbi.cb = cb;
	cbi.cb_data = user_data;

	g_hash_table_foreach(cf->tbl, _iter_cb, &cbi);
}

int appinfo_get_boolean(const struct appinfo *c, enum appinfo_type type)
{
	const char *v;

	v = appinfo_get_value(c, type);
	if (!v)
		return -1;

	if (!strcmp(v, "1") || !strcasecmp(v, "true"))
		return 1;

	if (!strcmp(v, "0") || !strcasecmp(v, "false"))
		return 0;

	errno = EFAULT;

	return -1;
}

