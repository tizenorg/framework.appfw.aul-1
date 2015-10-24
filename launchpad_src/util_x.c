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
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <X11/Xlib.h>
#include <X11/Xatom.h>

#include "simple_util.h"

static Atom a_pid;
static int (*x_old_error) (Display *, XErrorEvent *);


static pid_t __get_win_pid(Display *d, Window win);
static int __find_win(Display *d, Window *win, pid_t pid);
static int __raise_win(Display *d, Window win);
static int __cb_x_error(Display *disp, XErrorEvent *ev);

static pid_t __get_win_pid(Display *d, Window win)
{
	int r;
	pid_t pid;

	Atom a_type;
	int format;
	unsigned long nitems;
	unsigned long bytes_after;
	unsigned char *prop_ret;

	retv_if(d == NULL || !a_pid, -1);

	prop_ret = NULL;
	r = XGetWindowProperty(d, win, a_pid, 0, 1, False, XA_CARDINAL,
			&a_type, &format, &nitems, &bytes_after, &prop_ret);
	if (r != Success || prop_ret == NULL)
		return -1;

	if (a_type == XA_CARDINAL && format == 32)
		pid = *(unsigned long *)prop_ret;
	else
		pid = -1;

	XFree(prop_ret);

	return pid;
}

static int __find_win(Display *d, Window *win, pid_t pid)
{
	int r;
	pid_t p;
	unsigned int n;
	Window root, parent, *child;

	p = __get_win_pid(d, *win);
	if (p == pid)
		return 1;

	r = XQueryTree(d, *win, &root, &parent, &child, &n);
	if (r) {
		int i;
		int found = 0;

		for (i = 0; i < n; i++) {
			found = __find_win(d, &child[i], pid);
			if (found) {
				*win = child[i];
				break;
			}
		}
		XFree(child);

		if (found)
			return 1;
	}

	return 0;
}

static int __raise_win(Display *d, Window win)
{
	XWindowAttributes attr;
	attr.map_state = IsUnmapped;

	XMapRaised(d, win);

	XGetWindowAttributes(d, win, &attr);

	if (attr.map_state == IsUnmapped)
		_D("unmapped");
	else if (attr.map_state == IsUnviewable)
		_D("unviewable");
	else if (attr.map_state == IsViewable)
		_D("viewable");

	retv_if(attr.map_state != IsViewable, -1);

	XSetInputFocus(d, win, RevertToPointerRoot, CurrentTime);

	return 0;
}

int x_util_raise_win(pid_t pid)
{
	int r;
	int found;
	Display *d;
	Window win;

	if (pid < 1)
		return -1;

	r = kill(pid, 0);
	if (r == -1)
		return -1;

	d = XOpenDisplay(NULL);
	retv_if(d == NULL, -1);

	win = XDefaultRootWindow(d);

	if (!a_pid)
		a_pid = XInternAtom(d, "X_CLIENT_PID", True);

	found = __find_win(d, &win, pid);
	if (!found) {
		XCloseDisplay(d);
		_E("cannot found window with pid - %d", pid);
		return -1;
	}

	r = __raise_win(d, win);
	if (r < 0)
		_E("fail to raise win");

	XCloseDisplay(d);

	return r;
}

int x_util_get_default_size(double *w, double *h)
{
	Display *d;
	int screen_num;

	d = XOpenDisplay(NULL);
	if (d == NULL)
		return -1;

	screen_num = DefaultScreen(d);

	*w = DisplayWidth(d, screen_num);
	*h = DisplayHeight(d, screen_num);

	_D("Root Width = %lf, Height = %lf\n", *w, *h);

	XCloseDisplay(d);

	return 0;
}

static int __cb_x_error(Display *disp, XErrorEvent *ev)
{
	_E("X error received - Error Code = %d", ev->error_code);
	return 0;
}

int x_util_init()
{
	x_old_error = XSetErrorHandler(__cb_x_error);
	return 0;
}

int x_util_fini()
{
	XSetErrorHandler(x_old_error);
	return 0;
}

