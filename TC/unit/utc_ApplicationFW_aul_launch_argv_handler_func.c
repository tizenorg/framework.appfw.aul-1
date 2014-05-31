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
#include <tet_api.h>
#include <Ecore.h>

static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_ApplicationFW_aul_launch_argv_handler_func_01(void);
static void utc_ApplicationFW_aul_launch_argv_handler_func_02(void);

enum {
	NEGATIVE_TC_IDX = 0x01,
	POSITIVE_TC_IDX = 0x02,
};

struct tet_testlist tet_testlist[] = {
	{ utc_ApplicationFW_aul_launch_argv_handler_func_02, NEGATIVE_TC_IDX },
	{ utc_ApplicationFW_aul_launch_argv_handler_func_01, POSITIVE_TC_IDX },
	{ NULL, 0 }
};

static void startup(void)
{
}

static void cleanup(void)
{
	sleep(3);
}

/**
 * @brief Positive test case of aul_launch_argv_handler()
 */
static void utc_ApplicationFW_aul_launch_argv_handler_func_01(void)
{
	int r = 0;

	ecore_init();
	aul_launch_init(NULL,NULL);
   	r = aul_launch_argv_handler(0, NULL);

	if (r<0) {
		tet_infoline("aul_launch_argv_handler() failed in positive test case");
		tet_result(TET_FAIL);
		return;
	}
	tet_result(TET_PASS);
	ecore_shutdown();
}

/**
 * @brief Negative test case of ug_init aul_launch_argv_handler()
 */
static void utc_ApplicationFW_aul_launch_argv_handler_func_02(void)
{
	int r = 0;

   	r = aul_launch_argv_handler(0,NULL);

	if (r>=0) {
		tet_infoline("aul_launch_argv_handler() failed in negative test case");
		tet_result(TET_FAIL);
		return;
	}
	tet_result(TET_PASS);
}
