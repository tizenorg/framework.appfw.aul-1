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

#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include "aul.h"

/* ecore-glib integration */

#include <Ecore.h>

extern int aul_listen_app_dead_signal(int (*func) (int, void *), void *data);

void do_create()
{
	/* call real create callback*/
}

void do_resume()
{
	/* call real resume callback*/
	static int times = 0;
	printf("=================================\n");
	printf("resumed - %d\n", times++);
	printf("=================================\n");
}

static Eina_Bool send_result(void *data)
{
	bundle *kb;
	bundle *res_b;
	kb = (bundle *) data;

	aul_create_result_bundle(kb, &res_b);
	if (res_b == NULL)
		return 0;

	aul_send_service_result(res_b);
	bundle_free(res_b);

	bundle_free(kb);

	return 0;
}

static void prt_bundle(const char *key, const char *value, void *d)
{
	printf("bundle - key: %s, value: %s\n", key, value);
}

int do_start(void *data)
{
	bundle *kb = data;
	const char *tmp;
	struct timeval tv;
	struct timeval cur;
	struct timeval res;
	static int times = 0;

	printf("=================================\n");
	printf("start callback with glib - %d\n", times++);
	printf("=================================\n");

	tmp = bundle_get_val(kb, AUL_K_STARTTIME);
	if (tmp != NULL) {
		sscanf(tmp, "%ld/%ld", &tv.tv_sec, &tv.tv_usec);
		gettimeofday(&cur, NULL);
		timersub(&cur, &tv, &res);
		printf("=================================\n");
		printf("launched time = %ld sec %ld msec\n", res.tv_sec,
		       res.tv_usec / 1000);
		printf("=================================\n");
	}
	bundle_del(kb, AUL_K_STARTTIME);

	bundle_iterate(kb, prt_bundle, NULL);

	ecore_timer_add(5, send_result, bundle_dup(kb));

	return 0;
}

static int aul_handler(aul_type type, bundle *kb, void *data)
{
	bundle *b;

	switch (type) {
	case AUL_START:
		b = bundle_dup(kb);
		do_start((void *)b);
		bundle_free(b);
		break;
	case AUL_RESUME:
		do_resume();
		break;
	case AUL_TERMINATE:
		exit(0);
		break;
	}
	return 0;
}

int app_dead_handler(int pid, void *data)
{
	printf("===> %s : %d\n", __FUNCTION__, pid);
	return 0;
}

int app_launch_handler(int pid, void *data)
{
	printf("===> %s : %d\n", __FUNCTION__, pid);
	return 0;
}

__attribute__ ((visibility("default")))
int main(int argc, char **argv)
{
	ecore_init();

	do_create();

	if (aul_launch_init(aul_handler, NULL) < 0)
		printf("error aul_init\n");
	if (aul_launch_argv_handler(argc, argv) < 0)
		printf("error argv\n");

	aul_listen_app_dead_signal(app_dead_handler, NULL);

	aul_listen_app_launch_signal(app_launch_handler, NULL);

	if (fork() == 0) {
		printf("child test\n");
		exit(0);
	}

	ecore_main_loop_begin();
	return 0;
}

/* vi: set ts=8 sts=8 sw=8: */



/* vi: set ts=8 sts=8 sw=8: */
