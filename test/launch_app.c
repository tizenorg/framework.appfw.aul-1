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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <Ecore.h>
#include <bundle_internal.h>
#include "aul.h"

#define ROOT_UID 0
#define TMP_FILE "/tmp/.testpkg"

static char **gargv;
static int gargc;
bundle *kb = NULL;


static bundle *create_internal_bundle(int start)
{
	bundle *kb;
	int i;
	char arg[1024] = {0, };
	char* val_array[128];

	kb = bundle_create();
	for (i = start; i < gargc - 1; i++) {
		if ((i + 1) > gargc - 1)
			bundle_add(kb, gargv[i], " ");
		else {
			int j = 1;
			strncpy(arg, gargv[i + 1], 1023);
			val_array[0] = strtok(arg,",");
			while(1)
			{
				val_array[j] = strtok(NULL,",");
				if(val_array[j] == NULL)
					break;
				j++;
			}
			if(j==1)
				bundle_add(kb, gargv[i], gargv[i + 1]);
			else if(j>1)
				bundle_add_str_array(kb, gargv[i],
					(const char**)val_array, j);
		}
	}

	return kb;
}

int launch()
{
	int pid = -1;

	kb = create_internal_bundle(2);
	if (NULL == kb) {
		printf("bundle creation fail\n");
		return -1;
	}

	pid = aul_launch_app(gargv[1], kb);

	/* Write the package name to TMP_FILE*/
/*	fp = fopen(TMP_FILE, "w");
	if (fp == NULL)
		return -1;
	ret = fprintf(fp, "%d", pid);
	fclose(fp);
	if (ret < 0)
		return -1;*/

	return pid;
}

void print_usage(char *progname)
{
	printf("[usage] %s <pkgname> <key1> <val1> <key2> <val2> ...\n",
	       progname);
}

static int __launch_app_dead_handler(int pid, void *data)
{
	int listen_pid = (int) data;

	if(listen_pid == pid)
		ecore_main_loop_quit();

	return 0;
}

static Eina_Bool run_func(void *data)
{
	int pid = -1;
	const char *str = NULL;

	if ((pid = launch()) > 0) {
		printf("... successfully launched\n");
		str = bundle_get_val(kb, "__LAUNCH_APP_MODE__");

		if(str && strcmp(str, "SYNC") == 0 ) {
			aul_listen_app_dead_signal(__launch_app_dead_handler, (void *)pid);
		} else {
			ecore_main_loop_quit();
        }
	} else {
		printf("... launch failed\n");
		ecore_main_loop_quit();
	}

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}

	return 0;
}


int main(int argc, char **argv)
{
	if (argc < 2) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	ecore_init();

	gargc = argc;
	gargv = argv;

	ecore_idler_add(run_func, NULL);

	ecore_main_loop_begin();

	return 0;
}

