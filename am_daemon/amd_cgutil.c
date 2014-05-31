#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <mntent.h>


#include "amd_config.h"
#include "simple_util.h"
#include "amd_cgutil.h"

#define CFILE_RELEASE_AGENT "release_agent"
#define CFILE_NOTIFY_ON_RELEASE "notify_on_release"
#define CFILE_TASKS "tasks"

#define DEFAULT_MODE 0755

struct ctrl {
	enum ctrl_type ctrl;
	char *root; /* cginfo's mount_point + subsystem name */
};

struct cginfo {
	int refcnt;
	char *mount_point;
	struct ctrl ctrls[CTRL_MAX];
};

enum {
	_MNT_ROOT,
	_MNT_MGR,
	_MNT_CPU,
	_MNT_MEM,
	/* add type after adding mount information to mntinfos[] */
};

struct mntinfo {
	char *source;
	char *ftype; /* filesystem type */
	unsigned long flags;
	char *option;
};

static struct mntinfo mntinfos[] = {
	[_MNT_ROOT] = {
		"cgroup_root",
		"tmpfs",
		MS_NODEV | MS_NOSUID | MS_NOEXEC,
		NULL,
	},
	[_MNT_MGR] = {
		"daemon_mgr",
		"cgroup",
		MS_NODEV | MS_NOSUID | MS_NOEXEC,
		"none,name=daemon_mgr",
	},
	[_MNT_CPU] = {
		"cpuset",
		"cgroup",
		MS_NODEV | MS_NOSUID | MS_NOEXEC,
		"cpuset",
	},
	[_MNT_MEM] = {
		"memory",
		"cgroup",
		MS_NODEV | MS_NOSUID | MS_NOEXEC,
		"memory",
	},
	/* TODO: add more */
};

struct ctrlinfo {
	int mnt_type;
	char *name;
};

static struct ctrlinfo ctrlinfos[] = {
	[CTRL_MGR] = { _MNT_MGR, "mgr", },
#if defined(USE_CGROUP_CPU)
	[CTRL_CPU] = { _MNT_CPU, "cpuset", },
#endif
#if defined(USE_CGROUP_MEM)
	[CTRL_MEM] = { _MNT_MEM, "memory", },
#endif
};

static inline int _mount(const char *mount_point, struct mntinfo *mti)
{
	assert(mti);
	return mount(mti->source, mount_point, mti->ftype, mti->flags,
			mti->option);
}

static inline int _umount(const char *mount_point)
{
	return umount2(mount_point, MNT_DETACH);
}

static int _write_single(struct ctrl *ctr,
		const char *group, const char *file, const char *str)
{
	FILE *fp;
	char path[FILENAME_MAX];
	int r;

	assert(ctr);
	assert(file);

	if (!str)
		str = "";

	snprintf(path, sizeof(path), "%s/%s%s%s", ctr->root,
			group ? : "", group ? "/" : "", file);
	fp = fopen(path, "w");
	if (!fp) {
		_E("open: %s: %s", path, strerror(errno));
		return -1;
	}

	r = fputs(str, fp);
	if (r == EOF) {
		_E("write: %s,%s: %s", path, str, strerror(errno));
		r = -1;
	} else {
		r = 0;
	}

	fclose(fp);

	return r;
}

/*
static void _trunc_newline(char *buf, int sz)
{
	char *s;

	assert(buf);
	assert(sz > 0);

	s = buf;
	while (*s) {
		if (*s == '\r' || *s == '\n') {
			*s = '\0';
			break;
		}
		s++;
	}
}

static int _read_single(struct ctrl *ctr, const char *file, char *buf, int sz)
{
	FILE *fp;
	char path[FILENAME_MAX];
	char _buf[LINE_MAX];
	char *r;

	assert(ctr);
	assert(file);
	assert(buf);
	assert(sz > 0);

	snprintf(path, sizeof(path), "%s/%s", ctr->root, file);
	fp = fopen(path, "r");
	if (!fp) {
		_E("open: %s: %s", path, strerror(errno));
		return -1;
	}

	r = fgets(_buf, sizeof(_buf), fp);
	if (r == NULL) {
		_E("read: %s: %s", path, strerror(errno));
	} else {
		_trunc_newline(_buf, sizeof(_buf));
		snprintf(buf, sz, "%s", _buf);
	}

	fclose(fp);

	return r == NULL ? -1 : 0;
}
*/

static int _destroy(struct cginfo *cg)
{
	int i;
	int r;

	for (i = 0; i < sizeof(cg->ctrls)/sizeof(cg->ctrls[0]); i++) {
		struct ctrl *ctr = &cg->ctrls[i];

		if (ctr->root) {
			r = _umount(ctr->root);
			if (r == -1) {
				_E("unmount: %s: %s",
						ctr->root, strerror(errno));
				return -1;
			}
			free(ctr->root);
			ctr->root = NULL;
		}
	}

	if (cg->mount_point) {
		r = _umount(cg->mount_point);
		if (r == -1) {
			_E("unmount: %s: %s",
					cg->mount_point, strerror(errno));
			return -1;
		}
		free(cg->mount_point);
	}

	free(cg);

	return 0;
}

void cgutil_destroy(struct cginfo **cg)
{
	int r;

	if (!cg || !*cg)
		return;

	(*cg)->refcnt--;

	if ((*cg)->refcnt > 0)
		return;

	r = _destroy(*cg);
	if (r == -1)
		return;

	*cg = NULL;
}

static int check_cgroup_mount(const char *mount_point)
{
	struct mntent* mnt;
	const char* table = "/etc/mtab";
	FILE* fp;
	int	r = -1;
	fp = setmntent(table, "r");

	if (!fp)
		return r;

	while (mnt=getmntent(fp)) {
		if (strcmp(mount_point, mnt->mnt_dir) == 0) {
			r = 0;
			break;
		}
	}
	endmntent(fp);
	return r;
}

static int _mount_root(struct cginfo *cg, const char *mount_point)
{
	int r = 0;

	if (check_cgroup_mount(mount_point) < 0)
		r = _mount(mount_point, &mntinfos[_MNT_ROOT]);
	if (r == -1) {
		if (errno != EBUSY) {
			_E("mount: %s: %s", mount_point, strerror(errno));
			return -1;
		}
		_D("'%s' already mounted", mount_point);
	}

	cg->mount_point = strdup(mount_point);

	return 0;
}

static int _init_ctrl(struct ctrl *ctr, struct cginfo *cg, enum ctrl_type ctrl)
{
	int r;
	int mt;
	char path[FILENAME_MAX];

	assert(ctr);
	assert(ctrl >= 0);
	assert(ctrl < sizeof(ctrlinfos)/sizeof(ctrlinfos[0]));

	mt = ctrlinfos[ctrl].mnt_type;
	snprintf(path, sizeof(path), "%s/%s",
			cg->mount_point, ctrlinfos[ctrl].name);

	/* TODO: read /proc/cgroup and check the current type is enabled */

	r = mkdir(path, DEFAULT_MODE);
	if (r == -1) {
		if (errno != EEXIST) {
			_E("mkdir: %s: %s", path, strerror(errno));
			return -1;
		}
		_D("'%s' exist", path);
	}

	r = _mount(path, &mntinfos[mt]);
	if (r == -1) {
		if (errno != EBUSY) {
			_E("mount: %s: %s", path, strerror(errno));
			rmdir(path);
			return -1;
		}
		_D("'%s' already mounted", path);
	}

	ctr->ctrl = ctrl;
	ctr->root = strdup(path);

	return 0;
}

static int _set_release_agent(struct ctrl *ctr, const char *agent_path)
{
	int r;

	r = access(agent_path, X_OK);
	if (r == -1) {
		_E("'%s' is not executable: %s",
				agent_path, strerror(errno));
		return -1;
	}

	r = _write_single(ctr, NULL, CFILE_RELEASE_AGENT, agent_path);
	if (r == -1)
		return -1;

	r = _write_single(ctr, NULL, CFILE_NOTIFY_ON_RELEASE, "1");
	if (r == -1)
		return -1;

	return 0;
}

struct cginfo *cgutil_ref(struct cginfo *cg)
{
	if (cg)
		cg->refcnt++;

	return cg;
}

static int _create(struct cginfo *cg,
		const char *mount_point, const char *agent_path)
{
	int i;
	int r;

	r = _mount_root(cg, mount_point);
	if (r == -1)
		return -1;

	for (i = 0; i < sizeof(cg->ctrls)/sizeof(cg->ctrls[0]); i++) {
		r = _init_ctrl(&cg->ctrls[i], cg, i);
		if (r == -1)
			return -1;
	}

	r = _set_release_agent(&cg->ctrls[CTRL_MGR], agent_path);
	if (r == -1)
		return -1;

	return 0;
}

int cgutil_create(const char *mount_point, const char *agent_path,
		struct cginfo **cg)
{
	struct cginfo *_cg;
	int r;

	if (!mount_point || !*mount_point ||
			!agent_path || !*agent_path || !cg) {
		errno = EINVAL;
		_E("cgutil create: %s", strerror(errno));
		return -1;
	}

	_cg = calloc(1, sizeof(*_cg));
	if (!_cg) {
		_E("cgutil alloc: %s", strerror(errno));
		return -1;
	}

	r = _create(_cg, mount_point, agent_path);
	if (r == -1) {
		_destroy(_cg);
		return -1;
	}

	*cg = cgutil_ref(_cg);

	return 0;
}

int cgutil_create_group(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group)
{
	int r;
	struct ctrl *ctr;
	char path[FILENAME_MAX];

	assert(ctrl >= 0 && ctrl < CTRL_MAX);

	if (!cg || !group || !*group) {
		errno = EINVAL;
		_E("cgutil create group: %s", strerror(errno));
		return -1;
	}

	ctr = &cg->ctrls[ctrl];
	assert(ctr);

	snprintf(path, sizeof(path), "%s/%s", ctr->root, FILENAME(group));

	r = mkdir(path, DEFAULT_MODE);
	if (r == -1) {
		_E("cgutil create group: mkdir: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int cgutil_remove_group(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group)
{
	int r;
	struct ctrl *ctr;
	char path[FILENAME_MAX];

	assert(ctrl >= 0 && ctrl < CTRL_MAX);

	if (!cg || !group || !*group) {
		errno = EINVAL;
		_E("cgutil remove group: %s", strerror(errno));
		return -1;
	}

	ctr = &cg->ctrls[ctrl];
	assert(ctr);

	snprintf(path, sizeof(path), "%s/%s", ctr->root, FILENAME(group));

	r = rmdir(path);
	if (r == -1) {
		_E("cgutil remove group: rmdir: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int cgutil_exist_group(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group)
{
	int r;
	struct ctrl *ctr;
	char path[FILENAME_MAX];
	struct stat st;

	assert(ctrl >= 0 && ctrl < CTRL_MAX);

	if (!cg || !group || !*group) {
		errno = EINVAL;
		_E("cgutil exist group: %s", strerror(errno));
		return -1;
	}

	ctr = &cg->ctrls[ctrl];
	assert(ctr);

	snprintf(path, sizeof(path), "%s/%s", ctr->root, FILENAME(group));

	r = stat(path, &st);
	if (r == -1) {
		if (errno == ENOENT)
			return 0;

		_E("cgutil exist group: %s", strerror(errno));
		return -1;
	}

	/* stat() returns no error, then group exists */
	return 1;
}

int cgutil_group_add_pid(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group, pid_t pid)
{
	int r;
	struct ctrl *ctr;
	char buf[32]; /* 32 is enough for ineger number */

	assert(ctrl >= 0 && ctrl < CTRL_MAX);

	/* PID 1 is init's PID */
	if (!cg || !group || !*group || pid <= 1) {
		errno = EINVAL;
		_E("cgutil add pid: %s", strerror(errno));
		return -1;
	}

	ctr = &cg->ctrls[ctrl];
	assert(ctr);

	snprintf(buf, sizeof(buf), "%d", pid);

	r = _write_single(ctr, FILENAME(group), CFILE_TASKS, buf);
	if (r == -1)
		return -1;

	return 0;
}

static int _foreach_pid(struct ctrl *ctr, const char *group,
		cgutil_iter_pid_callback cb, void *user_data)
{
	int r;
	FILE *fp;
	char path[FILENAME_MAX];

	assert(ctr);
	assert(cb);

	snprintf(path, sizeof(path), "%s/%s/%s",
			ctr->root, FILENAME(group), CFILE_TASKS);
	fp = fopen(path, "r");
	if (!fp) {
		_E("open: %s: %s", path, strerror(errno));
		return -1;
	}

	while (!feof(fp)) {
		unsigned long l;

		r = fscanf(fp, "%lu", &l);
		if (r != 1)
			break;

		r = cb(user_data, group, l);
		if (r == -1)
			break;
	}

	fclose(fp);

	return 0;
}

int cgutil_group_foreach_pid(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group,
		cgutil_iter_pid_callback cb, void *user_data)
{
	struct ctrl *ctr;

	assert(ctrl >= 0 && ctrl < CTRL_MAX);

	if (!cg || !group || !*group || !cb) {
		errno = EINVAL;
		_E("cgutil foreach pid: %s", strerror(errno));
		return -1;
	}

	ctr = &cg->ctrls[ctrl];
	assert(ctr);

	return _foreach_pid(ctr, group, cb, user_data);
}

static int _foreach_group(struct ctrl *ctr,
		cgutil_iter_group_callback cb, void *user_data)
{
	int r;
	DIR *d;
	struct dirent *de;

	assert(ctr);
	assert(cb);

	d = opendir(ctr->root);
	if (!d) {
		_E("open: %s: %s", ctr->root, strerror(errno));
		return -1;
	}

	for (de = readdir(d); de; de = readdir(d)) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		r = cb(user_data, de->d_name);
		if (r == -1)
			break;
	}

	closedir(d);

	return 0;
}

int cgutil_foreach_group(struct cginfo *cg, enum ctrl_type ctrl,
		cgutil_iter_group_callback cb, void *user_data)
{
	struct ctrl *ctr;

	assert(ctrl >= 0 && ctrl < CTRL_MAX);

	if (!cg || !cb) {
		errno = EINVAL;
		_E("cgutil foreach group: %s", strerror(errno));
		return -1;
	}

	ctr = &cg->ctrls[ctrl];
	assert(ctr);

	return _foreach_group(ctr, cb, user_data);
}
