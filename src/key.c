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
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <poll.h>
#include <bundle.h>

#include "aul.h"
#include "aul_api.h"
#include "menu_db_util.h"
#include "simple_util.h"
#include "app_sock.h"
#include "aul_util.h"
#include "launch.h"


static int (*_aul_key_handler) (bundle *kb, void *data) = NULL;
static void *_aul_key_data = NULL;

extern GSourceFuncs funcs;

int app_key_event(bundle *kb)
{
	if (_aul_key_handler)
		_aul_key_handler(kb, _aul_key_data);
	return 0;
}

int aul_register_key_init_callback(
	int (*aul_handler) (bundle *, void *), void *data)
{
	/* Save start handler function in static var */
	_aul_key_handler = aul_handler;
	_aul_key_data = data;
	return 0;
}

SLPAPI int aul_key_init(int (*aul_handler) (bundle *, void *), void *data)
{
#ifdef _APPFW_FEATURE_AMD_KEY
	int fd;
	GPollFD *gpollfd;
	GSource *src;
	int ret;

	if (aul_handler != NULL)
		aul_register_key_init_callback(aul_handler, data);

	fd = aul_initialize();
	if (fd < 0)
		return fd;

	src = g_source_new(&funcs, sizeof(GSource));

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	if (gpollfd == NULL) {
		g_source_unref(src);
		return AUL_R_ERROR;
	}

	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __aul_glib_handler,
			      (gpointer) gpollfd, NULL);
	g_source_set_priority(src, G_PRIORITY_LOW);

	ret = g_source_attach(src, NULL);
	if (ret == 0)
		return AUL_R_ERROR;

	g_source_unref(src);
#endif
	return AUL_R_OK;
}

SLPAPI int aul_key_reserve()
{
#ifdef _APPFW_FEATURE_AMD_KE
	bundle *kb;
	int ret;

	kb = bundle_create();
	ret = app_send_cmd(AUL_UTIL_PID, APP_KEY_RESERVE, kb);
	bundle_free(kb);

	return ret;
#else
	return AUL_R_OK;
#endif
}

SLPAPI int aul_key_release()
{
#ifdef _APPFW_FEATURE_AMD_KE
	bundle *kb;
	int ret;

	kb = bundle_create();
	ret = app_send_cmd(AUL_UTIL_PID, APP_KEY_RELEASE, kb);
	bundle_free(kb);

	return ret;
#else
	return AUL_R_OK;
#endif
}
