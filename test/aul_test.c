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
#include <poll.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <Ecore.h>
#include <bundle_internal.h>

#include "menu_db_util.h"
#include "aul.h"
#include "aul_svc.h"
#define PERF_ACTIVATE
#include "perf.h"

#define QUERY_LEN	10240

static char **gargv;
static int gargc;
static char *cmd;
static int apn_pid;

typedef struct _test_func_t {
	char *name;
	int (*func) ();
	char *desc;
	char *usage;
} test_func_t;

static bundle *create_internal_bundle(int start)
{
	bundle *kb;
	int i;

	kb = bundle_create();
	for (i = start; i < gargc - 1; i++) {
		if ((i + 1) > gargc - 1)
			bundle_add(kb, gargv[i], " ");
		else
			bundle_add(kb, gargv[i], gargv[i + 1]);
	}

	return kb;
}

int launch_test()
{
	static int num = 0;
	int ret = 0;
	bundle *kb = NULL;

	kb = create_internal_bundle(3);
	if (NULL == kb) {
		return -1;
	}
	printf("[aul_launch_app %d test] %s \n", num++, gargv[2]);

	ret = aul_launch_app(gargv[2], kb);

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}
	return ret;
}

int launch_test_async()
{
	static int num = 0;
	int ret = 0;
	bundle *kb = NULL;

	kb = create_internal_bundle(3);
	if (NULL == kb) {
		return -1;
	}
	printf("[aul_launch_app %d test] %s \n", num++, gargv[2]);

	ret = aul_launch_app_async(gargv[2], kb);

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}
	return ret;
}

int dbus_launch_test()
{
	bundle *kb = NULL;
	int ret = 0;

	kb = create_internal_bundle(3);

	if (NULL == kb) {
		return -1;
	}

	ret = aul_launch_app(gargv[2], kb);

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}

	return ret;
}

int open_test()
{
	static int num = 0;

	printf("[aul_open_app %d test] %s \n", num++, gargv[2]);
	return aul_open_app(gargv[2]);
}

int resume_test()
{
	static int num = 0;

	printf("[aul_open_app %d test] %s \n", num++, gargv[2]);
	return aul_resume_app(gargv[2]);
}

int resume_pid_test()
{
	static int num = 0;
	printf("[aul_resume_pid %d test] %d \n", num++, apn_pid);
	return aul_resume_pid(apn_pid);
}

int term_pid_test()
{
	static int num = 0;
	printf("[aul_term_pid %d test] %d \n", num++, apn_pid);
	return aul_terminate_pid(apn_pid);
}

int term_pid_without_restart_test()
{
	static int num = 0;
	printf("[aul_term_pid_without_restart %d test] %d \n", num++, apn_pid);
	return aul_terminate_pid_without_restart(apn_pid);
}

int term_req_pid_test()
{
	static int num = 0;
	printf("[aul_subapp_terminate_request_pid %d test] %d \n", num++, apn_pid);
	return aul_subapp_terminate_request_pid(apn_pid);
}

int pause_test()
{
	static int num = 0;

	printf("[aul_pause_app %d test] %s \n", num++, gargv[2]);
	return aul_pause_app(gargv[2]);
}

int pause_pid_test()
{
	static int num = 0;

	printf("[aul_pause_pid %d test] %d \n", num++, apn_pid);
	return aul_pause_pid(apn_pid);
}

static test_func_t scn_func[] = {
	{"n", launch_test, "launch_test", ""},
	{"n", launch_test, "launch_test", ""},
	{"n", resume_test, "open_test", ""},
	{"n", resume_test, "open_test", ""},
	{"p", resume_pid_test, "resume_pid_test", ""},
	{"p", resume_pid_test, "resume_pid_test", ""},
	{"p", term_pid_test, "term_pid_test", ""},
	{"n", resume_test, "open_test", ""},
	{"n", launch_test, "launch_test", ""}
};

static Eina_Bool run_all_test(void *data)
{
	static int pos = 0;
	int ret;

	if (pos > sizeof(scn_func) / sizeof(test_func_t) - 1) {
		printf("all internal test done\n");
		ecore_main_loop_quit();
		return 0;
	}

	if (strncmp(scn_func[pos].name, "n", 1) == 0) {
		printf("[test %d] %s , pkgname = %s\n", pos, scn_func[pos].desc,
		       gargv[2]);
		apn_pid = scn_func[pos].func();
		printf("... return pid = %d\n", apn_pid);
	} else {
		printf("[test %d] %s , pid = %d\n", pos, scn_func[pos].desc,
		       apn_pid);
		ret = scn_func[pos].func();
		printf("... return res = %d\n", ret);
	}
	pos++;

	return 1;
}

int all_test()
{
	ecore_timer_add(2, run_all_test, NULL);
	return 0;
}

int is_run_test()
{
	if (aul_app_is_running(gargv[2]))
		printf("... %s is running\n", gargv[2]);
	else
		printf("... %s is not running\n", gargv[2]);

	return 0;
}

int get_pid_test()
{
	printf("[aul_app_get_pid %s test] \n", gargv[2]);
	return aul_app_get_pid(gargv[2]);
}

int get_pid_cache_test()
{
	printf("[aul_app_get_pid_cache %s test] \n", gargv[2]);
	return aul_app_get_pid_cache(gargv[2]);
}

int iterfunc(const aul_app_info *info, void *data)
{
	printf("\t==========================\n");
	printf("\t pkg_name: %s\n", info->appid);
	printf("\t app_path: %s\n", info->app_path);
	printf("\t running pid: %d\n", info->pid);
	printf("\t==========================\n");

	return 0;
}

int get_allpkg_test()
{
	static int num = 0;
	printf("[aul_app_get_ruuning_app_info %d test] \n", num++);
	return aul_app_get_running_app_info(iterfunc, NULL);
}

int get_pkgpid_test()
{
	int pid = 0;
	static int num = 0;
	char buf[MAX_LOCAL_BUFSZ];

	printf("[aul_app_get_appid_bypid %d test] \n", num++);
	pid = atoi(gargv[2]);

	if (aul_app_get_appid_bypid(pid, buf, sizeof(buf)) < 0)
		printf("no such pkg by %d\n", pid);
	else
		printf("pkgname = %s, pid = %d\n", buf, pid);

	return 0;
}

int get_mime_file_test()
{
	static int num = 0;
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	printf("[aul_get_mime_from_file %d test] %s \n", num++, gargv[2]);
	ret = aul_get_mime_from_file(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mime type = %s\n", buf);
	return ret;
}

int get_mime_content_test()
{
	static int num = 0;
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	printf("[aul_get_mime_from_content %d test] %s \n", num++, gargv[2]);
	ret = aul_get_mime_from_content(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mime type = %s\n", buf);
	return ret;
}

int aul_get_mime_icon_test()
{
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	ret = aul_get_mime_icon(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mimetype %s : iconname = %s\n", gargv[2], buf);
	return ret;
}

int aul_get_mime_description_test()
{
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	ret = aul_get_mime_description(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mimetype %s : description = %s\n", gargv[2], buf);
	return ret;
}

int aul_get_mime_extension_test()
{
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	ret = aul_get_mime_extension(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mimetype %s : extension = %s\n", gargv[2], buf);
	return ret;
}

static void print_menu_db_info(const app_info_from_db *info)
{
	if (info == NULL) {
		printf("pkg %s no found\n", gargv[2]);
		return;
	}

	printf("\t==========================\n");
	printf("\t pkg_name: %s\n", info->pkg_name);
	printf("\t app_path: %s\n", info->app_path);
	printf("\t is_minst: %d\n", 0);
	printf("\t==========================\n");
}

static int get_pkg_func()
{
	app_info_from_db *info;

	info = _get_app_info_from_db_by_pkgname(gargv[2]);
	print_menu_db_info(info);
	if (info)
		_free_app_info_from_db(info);

	return 0;
}

static char *status_text[] = {
	"STATUS_LAUNCHING",
	"STATUS_CREATED",
	"STATUS_FOCUS",
	"STATUS_VISIBLE",
	"STATUS_BG",
	"STATUS_DYING",
	"STATUS_HOME",
	"STATUS_NORESTART",
};

static int get_status_pid()
{
	int ret;
	ret = aul_app_get_status_bypid(apn_pid);

	printf("pid: %d status: %d ", apn_pid, ret);
	if (ret >= STATUS_LAUNCHING && ret <= STATUS_NORESTART)
		printf("(%s)", status_text[ret]);

	printf("\n");

	return 0;
}

static int get_last_caller_pid()
{
	int ret;
	int pid;

	pid = atoi(gargv[2]);
	ret = aul_app_get_last_caller_pid(pid);
	printf("pid: %d, last caller pid: %d\n", pid, ret);
	return ret;
}

static int update_running_list()
{
	aul_running_list_update(gargv[2], gargv[3], gargv[4]);

	return 0;
}

static int set_group_test()
{
	int owner_pid;
	int child_pid;

	owner_pid = atoi(gargv[2]);
	child_pid = atoi(gargv[3]);
	aul_set_process_group(owner_pid, child_pid);

	return 0;
}

static int get_group_test()
{
	char *str;

	str = aul_get_group_info();
	printf("%s\n", str);
	free(str);

	return 0;
}

/** AUL SVC internal private key */
#define AUL_SVC_K_OPERATION "__APP_SVC_OP_TYPE__"
/** AUL SVC internal private key */
#define AUL_SVC_K_URI       "__APP_SVC_URI__"
/** AUL SVC internal private key */
#define AUL_SVC_K_MIME      "__APP_SVC_MIME_TYPE__"
/** AUL SVC internal private key */
#define AUL_SVC_K_CATEGORY  "__APP_SVC_CATEGORY__"
/** AUL SVC internal private key */

static int iter_svc_fn(const char *appid, void *data)
{
	printf("matched : %s\n", appid);
	return 0;
}

static int get_svc_list()
{
	int i = 2;
	int ret = 0;
	bundle *b = NULL;
	if (gargc < 3 || (gargc - 2) % 2 == 1) {
		printf("[usage] get_svc_list --operation <operation> --mime <mime> --uri <uri>\n");
		return -1;
	}

	b = bundle_create();
	if (!b) {
		printf("out of memory\n");
		return -1;
	}

	for (i = 2; i < gargc; i+=2) {
		if (strcmp(gargv[i], "--operation") == 0) {
			bundle_add(b, AUL_SVC_K_OPERATION, gargv[i + 1]);
		}
		else if (strcmp(gargv[i], "--mime") == 0) {
			bundle_add(b, AUL_SVC_K_MIME, gargv[i + 1]);
		}
		else if (strcmp(gargv[i], "--uri") == 0) {
			bundle_add(b, AUL_SVC_K_URI, gargv[i + 1]);
		}
		else if (strcmp(gargv[i], "--category") == 0) {
			bundle_add(b, AUL_SVC_K_CATEGORY, gargv[i + 1]);
		}
	}

	printf("start aul_svc_get_list\n");
	ret = aul_svc_get_list(b, iter_svc_fn, NULL);
	printf("end aul_svc_get_list\n");
	bundle_free(b);

	return ret;
}

/*
static int set_pkg_func()
{
	char* pkgname;
	char* apppath;
	char* appname;
	char query[QUERY_LEN];

	pkgname = gargv[2];
	apppath = gargv[3];

	appname = strrchr(apppath,'/')+1;
	snprintf(ai.app_icon_path, PATH_LEN, "aul_test_icon_path/%d",getpid());
	snprintf(ai.desktop_path, PATH_LEN,
		"aul_test_desktop_path/%d",getpid());

	snprintf (query, sizeof(query), "insert into "TABLE_MENU"(\
	pkg_name,\
	app_path,\
	app_name,\
	app_icon_path,\
	desktop_path)\
	values ('%s', '%s', '%s', '%s', '%s')",
	pkgname,
	apppath,
	appname,
	record->app_icon_path,
	record->desktop_path,
	);

	// TODO: record_add is not supported anymore; use AIL
	if (record_add(ADD_ICON, &ai)){
		printf("set pkg success\n");
		return 0;
	}
	else{
		printf("set pkg fail\n");
		return -1;
	}
}

static int del_pkg_func()
{
	app_info ai;

	memset(&ai, 0, sizeof(app_info));
	snprintf(ai.pkg_name, NAME_LEN, "%s", gargv[2]);

	// TODO: record_add is not supported anymore; use AIL
	if(record_delete(DELETE_MENU, &ai)){
		printf("del pkg success\n");
		return 0;
	}
	else {
		printf("del pkg fail\n");
		return -1;
	}
}
*/

static int test_regex()
{
	char *token;
	char mime[MAX_LOCAL_BUFSZ];
	char *saveptr;

	INIT_PERF(NULL);

	printf("=======================\n");

	token = strtok_r(gargv[2], " \t\n,.()", &saveptr);
	if (aul_get_mime_from_content(token, mime, sizeof(mime)) == AUL_R_OK)
		printf("found %s %s\n", mime, token);

	while (token) {
		token = strtok_r(NULL, " \t\n,()", &saveptr);
		if (aul_get_mime_from_content(token, mime, sizeof(mime)) ==
		    AUL_R_OK)
			printf("found %s %s\n", mime, token);
	}

	PERF("======= parse end =====\n");
	return 0;
}

static test_func_t test_func[] = {
	{"launch",launch_test,"aul_launch_app test",
		"[usage] launch <pkgname> <key1> <val1> <key2> <val2> ..."},
	{"launch_async",launch_test_async,"aul_launch_app test",
		"[usage] launch_async <pkgname> <key1> <val1> <key2> <val2> ..."},
	{"open",open_test,"aul_open_app test",
		"[usage] open <pkgname>" },
	{"resume",resume_test,"aul_resume_app test",
		"[usage] resume <pkgname>" },
	{"resume_pid",resume_pid_test,"aul_resume_pid test",
		"[usage] resume_pid <pid>" },
	{"term_pid", term_pid_test,"aul_terminate_pid test",
		"[usage] term_pid <pid>" },
	{"term_pid_without_restart", term_pid_without_restart_test,"aul_terminate_pid_without_restart test",
		"[usage] term_pid_without_restart <pid>" },
	{"term_req_pid", term_req_pid_test,"aul_subapp_terminate_request_pid test",
		"[usage] term_req_pid <pid>" },
	{"dbuslaunch", dbus_launch_test,"launch by dbus auto activation",
		"[usage] term_pid <pid>" },
	{"all",all_test,"test based on predefine scenario",
		"[usage] all <pkgname>"},

	{"is_run", is_run_test,"aul_is_running test",
		"[usage] is_run <pkgname>"},
	{"getallpkg", get_allpkg_test, "aul_app_get_running_app_info test",
		"[usage] getallpkg all"},
	{"getpkgpid", get_pkgpid_test, "aul_app_get_appid_bypid test",
		"[usage] getpkgpid <pid>"},

	{"get_mime_file", get_mime_file_test, "aul_get_mime_from_file test",
		"[usage] get_mime_file <filename>"},
	{"get_mime_content", get_mime_content_test, "aul_get_mime_from_content",
		"[usage] get_mime_content <content>"},

	{"get_mime_icon", aul_get_mime_icon_test, "aul_get_mime_icon test",
		"[usage] get_mime_icon <mimetype>"},
	{"get_mime_desc", aul_get_mime_description_test, "aul_get_mime_description test",
		"[usage] get_mime_desc <mimetype>"},
	{"get_mime_ext", aul_get_mime_extension_test, "aul_get_mime_extension test",
		"[usage] get_mime_ext <mimetype>"},

	{"test_regex", test_regex, "regular expression parser test",
		"[usage] test_regex <full text>"},

	{"getpkg", get_pkg_func, "get package",
	      	"[usage] getpkg <pkgname>"},
	{"update_list", update_running_list, "update running list",
	      	"[usage] update_list <appid> <app_path> <pid>"},

	{"pause",pause_test,"aul_pause_app test",
		"[usage] pause <pkgname>" },
	{"pause_pid",pause_pid_test,"aul_pause_pid test",
		"[usage] pause_pid <pid>" },

	{"get_pid", get_pid_test, "aul_get_pid test",
		"[usage] get_pid <pkgname>"},
	{"get_pid_cache", get_pid_cache_test, "aul_get_pid_cache test",
		"[usage] get_pid_cache <pkgname>"},

	{"get_status_pid", get_status_pid, "aul_app_get_status_bypid test",
		"[usage] get_status_pid <pid>"},
	{"set_group", set_group_test, "set_group_test",
	      	"[usage] set_group <pid> <pid>"},
	{"get_group", get_group_test, "get_group_test",
		"[usage] get_group"},
	{"get_svc_list", get_svc_list, "aul_svc_get_list test",
		"[usage] get_svc_list --operation <operation> --mime <mime> --uri <uri>"},
	{"get_last_caller_pid", get_last_caller_pid, "aul_app_get_last_caller_pid test",
		"[usage] get_last_caller_pid <pid>"},

/*
	{"setpkg", set_pkg_func, "set package",
	      	"[usage] setpkg <pkgname> <apppath>"},
	{"delpkg", del_pkg_func, "del package",
	      	"[usage] getpkg <pkgname>"},
*/
};

int callfunc(char *testname)
{
	test_func_t *tmp;
	int res;
	int i;

	for (i = 0; i < sizeof(test_func) / sizeof(test_func_t); i++) {
		tmp = &test_func[i];
		if (strcmp(testname, tmp->name) == 0) {
			res = tmp->func();
			if (strcmp(testname, "all")) {
				if (res < 0)
					printf("... test failed\n");
				else
					printf("... test successs ret = %d\n",
					       res);
			}
		}
	}
	return 0;
}

int dead_tracker(int pid, void *data)
{
	printf("[DEAD] pid = %d dead\n", pid);
	return 0;
}

void print_usage(char *progname)
{
	test_func_t *tmp;
	int i;

	printf("[usage] %s <cmd> ...\n", progname);
	printf(" - available cmd list\n");

	for (i = 0; i < sizeof(test_func) / sizeof(test_func_t); i++) {
		tmp = &test_func[i];
		printf("\t%s : %s\n", tmp->name, tmp->desc);
		printf("\t\t%s\n", tmp->usage);
	}

	printf("[note] getpkg/setpkg/delpkg/init_defapp_mime "
		"cmd is internal purpose\n");
}

static Eina_Bool run_func(void *data)
{
	callfunc(cmd);

	if (strcmp(cmd, "launch_res") == 0 || strcmp(cmd, "all") == 0
	    || strcmp(cmd, "dbuslaunch") == 0
	    || strcmp(cmd, "open_svc_res") == 0)
		return 0;
	else
		ecore_main_loop_quit();

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		print_usage(argv[0]);
		exit(0);
	}

	ecore_init();

	cmd = argv[1];
	gargc = argc;
	gargv = argv;
	apn_pid = atoi(argv[2]);

	/*aul_listen_app_dead_signal(dead_tracker,NULL); */
	/*aul_listen_app_dead_signal(NULL,NULL); */

	ecore_idler_add(run_func, NULL);

	ecore_main_loop_begin();

	return 0;
}

/* vi: set ts=8 sts=8 sw=8: */

