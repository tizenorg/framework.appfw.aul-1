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
	AIT_STATUS,
	AIT_POOL,
	AIT_COMPTYPE,
};

int appinfo_init(struct appinfomgr **cf);
void appinfo_fini(struct appinfomgr **cf);

const struct appinfo *appinfo_insert(struct appinfomgr *cf, const char *filename);
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
