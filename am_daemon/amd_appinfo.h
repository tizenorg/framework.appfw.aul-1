#ifndef __AUL_AMD_APPINFO_H_
#define __AUL_AMD_APPINFO_H_

struct appinfomgr;
struct appinfo;

enum appinfo_type {
	AIT_NAME,
	AIT_COMP,
	AIT_EXEC,
	AIT_TYPE,
	AIT_ONBOOT, /* start on boot: boolean */
	AIT_RESTART, /* auto restart: boolean */
	AIT_MULTI,
	AIT_HWACC,
	AIT_PERM,
	AIT_PKGID,
	AIT_TASKMANAGE,
	AIT_PRELOAD,
	AIT_INDICATOR_DISP,
	AIT_EFFECTIMAGEPORT,
	AIT_EFFECTIMAGELAND,
#ifdef _APPFW_FEATURE_CHANGEABLE_COLOR
	AIT_EFFECTTYPE,
#endif
	AIT_STATUS,
#ifdef _APPFW_FEATURE_PROCESS_POOL
	AIT_POOL,
#endif
	AIT_COMPTYPE,
#ifdef _APPFW_FEATURE_MULTI_INSTANCE
	AIT_MULTI_INSTANCE,
	AIT_MULTI_INSTANCE_MAINID,
	AIT_TOGGLE_ORDER,
#endif
#ifdef _APPFW_FEATURE_TTS_MODE
	AIT_TTS,
#endif
#ifdef _APPFW_FEATURE_ULTRA_POWER_SAVING_MODE
	AIT_UPS,
#endif
#ifdef _APPFW_FEATURE_COOLDOWN_MODE_SUPPORT
	AIT_COOLDOWN,
#endif
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	AIT_TEP,
	AIT_STORAGE_TYPE,
#endif
	AIT_ALLOWED_BG,
	AIT_API_VER,
	AIT_LAUNCH_MODE,
#ifdef _APPFW_FEATURE_EFFECTIVE_APPID
	AIT_EFFECTIVE_APPID,
#endif
#ifdef _APPFW_FEATURE_PRIVATE_SERVICE
	AIT_VISIBILITY,
#endif
	AIT_MAX
};

#define APP_TYPE_SERVICE	"svcapp"
#define APP_TYPE_UI			"uiapp"
#define APP_TYPE_WIDGET		"widgetapp"
#define APP_TYPE_WATCH		"watchapp"

int appinfo_init(struct appinfomgr **cf);
void appinfo_fini(struct appinfomgr **cf);

const struct appinfomgr *appinfo_insert(struct appinfomgr *cf, const char *filename);
void appinfo_delete(struct appinfomgr *cf, const char *filename);

const struct appinfo *appinfo_find(struct appinfomgr *cf, const char *filename);
const char *appinfo_get_value(const struct appinfo *c, enum appinfo_type type);
const char *appinfo_set_value(struct appinfo *c, enum appinfo_type type, const char* val);
const char *appinfo_get_filename(const struct appinfo *c);
int appinfo_get_boolean(const struct appinfo *c, enum appinfo_type type);

typedef void (*appinfo_iter_callback)(void *user_data,
		const char *filename, const struct appinfo *c);
void appinfo_foreach(struct appinfomgr *cf, appinfo_iter_callback cb, void *user_data);

#endif /* __AUL_AMD_APPINFO_H_ */
