
#ifndef __AUL_AMD_CGROUP_UTIL_H__
#define __AUL_AMD_CGROUP_UTIL_H__

enum ctrl_type {
	CTRL_MGR, /* for manager */
#if defined(USE_CGROUP_CPU) /* not implemented */
	CTRL_CPU, /* cpuset */
#endif
#if defined(USE_CGROUP_MEM) /* not implemented */
	CTRL_MEM, /* memory */
#endif
	/* TODO: add more */
	CTRL_MAX,
};

struct cginfo;

int cgutil_create(const char *mount_point, const char *agent_path,
		struct cginfo **cg);
void cgutil_destroy(struct cginfo **cg);

struct cginfo *cgutil_ref(struct cginfo *cg);
#define cgutil_unref(cg) cgutil_destroy(cg)


int cgutil_create_group(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group);
int cgutil_remove_group(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group);
int cgutil_exist_group(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group);

typedef int (*cgutil_iter_group_callback)(void *user_data, const char *group);
int cgutil_foreach_group(struct cginfo *cg, enum ctrl_type ctrl,
		cgutil_iter_group_callback cb, void *user_data);


int cgutil_group_add_pid(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group, pid_t pid);

typedef int (*cgutil_iter_pid_callback)(void *user_data, const char *group,
		pid_t pid);
int cgutil_group_foreach_pid(struct cginfo *cg,
		enum ctrl_type ctrl, const char *group,
		cgutil_iter_pid_callback cb, void *user_data);

#endif /* __AUL_AMD_CGROUP_UTIL_H__ */
