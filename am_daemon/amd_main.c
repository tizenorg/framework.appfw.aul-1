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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <Ecore_X.h>
#include <Ecore_Input.h>
#include <utilX.h>
#include <Ecore.h>
#include <Evas.h>
#include <aul.h>
#include <vconf.h>
#include <ail.h>
#include <glib.h>

#include "amd_config.h"
#include "simple_util.h"
#include "aul_util.h"
#include "amd_appinfo.h"
#include "amd_cgutil.h"
#include "amd_key.h"
#include "amd_status.h"
#include "amd_launch.h"
#include "amd_request.h"

#ifndef MOUNT_PATH
#  define MOUNT_PATH "/sys/fs/cgroup"
#endif

#ifndef AGENT_PATH
#  define AGENT_PATH "/usr/bin/daemon-manager-release-agent"
#endif

#define WINDOW_READY	"/tmp/.wm_ready"

typedef struct _window_watch {
	int watch_fd;
	int win_watch_wd;
	Ecore_Fd_Handler *win_watch_ewd;
} _window_watch_t;
static _window_watch_t *win_info_t = NULL;

static int __app_dead_handler(int pid, void *data);
static int __init();

extern int _status_init(struct amdmgr* amd);

static int __app_dead_handler(int pid, void *data)
{
	_unregister_key_event(pid);
	_status_remove_app_info_list(pid);
	return 0;
}

static void __start_cb(void *user_data,
		const char *filename, const struct appinfo *ai)
{
	/*struct amdmgr *amd = user_data;*/
	const char *componet = NULL;
	int r;

	componet = appinfo_get_value(ai, AIT_COMPTYPE);

	r = appinfo_get_boolean(ai, AIT_ONBOOT);

	if (r == 1 && strncmp(componet, "svcapp", 6) == 0)
	{
		const char *pkgid = appinfo_get_value(ai, AIT_PKGID);
		_D("start service - %s", pkgid);

		_start_srv(ai, NULL);
	}
}

static void _start_services(struct amdmgr *amd)
{
	appinfo_foreach(amd->af, __start_cb, amd);
}

static int __booting_done_handler(int pid, void *data)
{
	_start_services((struct amdmgr*)data);

	return 0;
}

static gboolean _check_window_ready(void)
{
	if (access(WINDOW_READY, R_OK) == 0)
		return true;
	else
		return false;
}

static void __window_init(void)
{
	ecore_x_init(NULL);
	_set_atom_effect();
#ifndef __i386__
	_key_init();
#endif
}

static Eina_Bool _window_cb(void *data, Ecore_Fd_Handler * fd_handler)
{
	int fd;
	char buf[FILENAME_MAX];
	ssize_t len = 0;
	struct inotify_event* event;

	if (ecore_main_fd_handler_active_get(fd_handler, ECORE_FD_ERROR)) {
		_E("An error has occurred. Stop watching this fd and quit");
		return ECORE_CALLBACK_CANCEL;
	}

	fd = ecore_main_fd_handler_fd_get(fd_handler);
	if(fd < 0) {
		_E("ecore_main_fd_handler_fd_get error");
		return ECORE_CALLBACK_CANCEL;
	}
	len = read(fd, buf, FILENAME_MAX);

	event = (struct inotify_event*) &buf[0];

	_D("filename : %s", event->name);

	if (access(WINDOW_READY, R_OK) == 0) {
		__window_init();
		if (win_info_t) {
			ecore_main_fd_handler_del(win_info_t->win_watch_ewd);
			inotify_rm_watch(win_info_t->watch_fd, win_info_t->win_watch_wd);
			free(win_info_t);
			win_info_t = NULL;
		}
	}

	return ECORE_CALLBACK_RENEW;
}

static void _register_window_init(void)
{
	win_info_t = malloc(sizeof(_window_watch_t));
	if (!win_info_t) {
		_E("Unable to allocate memory. don't init widow\n");
		return;
	}
	win_info_t->watch_fd = inotify_init();
	win_info_t->win_watch_wd = inotify_add_watch(win_info_t->watch_fd, "/tmp", IN_CREATE);
	win_info_t->win_watch_ewd = ecore_main_fd_handler_add(win_info_t->watch_fd,
						    ECORE_FD_READ, _window_cb, NULL, NULL, NULL);
}

static void _window_init(void)
{
	if (_check_window_ready())
		__window_init();
	else
		_register_window_init();
}

static int __init()
{
	struct amdmgr amd;

	ecore_init();
	evas_init();
	ecore_event_init();

	appinfo_init(&amd.af);
	cgutil_create(MOUNT_PATH, AGENT_PATH, &amd.cg);
	_requset_init(&amd);
	_launch_init(&amd);
	_status_init(&amd);
	_window_init();

	aul_listen_app_dead_signal(__app_dead_handler, NULL);

	aul_listen_booting_done_signal(__booting_done_handler, &amd);

	return 0;
}

gboolean  __amd_ready(gpointer user_data)
{
	int handle;

	handle = creat("/tmp/amd_ready", S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	if (handle != -1)
		close(handle);

	return FALSE;
}

int main(int argc, char *argv[])
{
	if (__init() != 0){
		_E("AMD Initialization failed!\n");
		return -1;
	}

	g_idle_add(__amd_ready, NULL);

	ecore_main_loop_begin();

	return 0;
}
