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


#include <glib.h>
#include <poll.h>
#include <bundle.h>
#include "aul.h"
#include "aul_api.h"
#include "launch.h"
#include "simple_util.h"
#include <Ecore.h>

static GSource *src;

static gboolean __aul_glib_check(GSource *src);
static gboolean __aul_glib_dispatch(GSource *src, GSourceFunc callback,
				  gpointer data);
static gboolean __aul_glib_prepare(GSource *src, gint *timeout);
static gboolean __app_start_internal(gpointer data);

static void __aul_glib_finalize(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		g_free(tmp);

		fd_list = fd_list->next;
	} while (fd_list);

	return;
}

static gboolean __aul_glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		if ((tmp->revents & (POLLIN | POLLPRI)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __aul_glib_dispatch(GSource *src, GSourceFunc callback,
				  gpointer data)
{
	callback(data);
	return TRUE;
}

static gboolean __aul_glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

GSourceFuncs funcs = {
	.prepare = __aul_glib_prepare,
	.check = __aul_glib_check,
	.dispatch = __aul_glib_dispatch,
	.finalize = __aul_glib_finalize
};

gboolean __aul_glib_handler(gpointer data)
{
	GPollFD *gpollfd = (GPollFD *) data;
	aul_sock_handler(gpollfd->fd);
	return TRUE;
}

static gboolean __app_start_internal(gpointer data)
{
	bundle *kb;

	kb = (bundle *) data;
	app_start(kb);
	bundle_free(kb);

	return 0;
}

SLPAPI int aul_launch_init(
	int (*aul_handler) (aul_type type, bundle *, void *), void *data)
{
	int fd;
	GPollFD *gpollfd;
	int ret;

	if (aul_handler != NULL)
		aul_register_init_callback(aul_handler, data);

	fd = aul_initialize();
	if (fd < 0)
		return fd;

	src = g_source_new(&funcs, sizeof(GSource));

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	if (gpollfd == NULL) {
		_E("out of memory");
		g_source_unref(src);
		close(fd);
		return AUL_R_ERROR;
	}

	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __aul_glib_handler,
			      (gpointer) gpollfd, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);

	ret = g_source_attach(src, NULL);
	if (ret == 0)
		return AUL_R_ERROR;

	g_source_unref(src);

	return AUL_R_OK;
}

SLPAPI int aul_launch_fini()
{
	g_source_destroy(src);
	return AUL_R_OK;
}

SLPAPI int aul_launch_argv_handler(int argc, char **argv)
{
	bundle *b;

	if (!aul_is_initialized())
		return AUL_R_ENOINIT;

	b = bundle_import_from_argv(argc, argv);
	if (b == NULL) {
		_E("bundle for APP_START is NULL");
	}
	if (g_idle_add(__app_start_internal, b) > 0)
		return AUL_R_OK;
	else
		return AUL_R_ERROR;
}

SLPAPI int aul_launch_argv_handler_for_efl(int argc, char **argv)
{
	bundle *b = NULL;

	Ecore_Idler *idler = NULL;

	if (!aul_is_initialized())
		return AUL_R_ENOINIT;

	b = bundle_import_from_argv(argc, argv);
	if (b == NULL) {
		_E("bundle for APP_START is NULL");
	}

	idler = ecore_idler_add(__app_start_internal, b);
	if (idler)
		return AUL_R_OK;
	else
		return AUL_R_ERROR;
}

SLPAPI int aul_launch_local(bundle *b)
{
	if (!aul_is_initialized())
		return AUL_R_ENOINIT;

	if (b == NULL) {
		_E("bundle for APP_START is NULL");
	}
	if (g_idle_add(__app_start_internal, b) > 0)
		return AUL_R_OK;
	else
		return AUL_R_ERROR;
}

