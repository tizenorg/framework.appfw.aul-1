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


#ifndef __MIDA_H__
#define __MIDA_H__

#include <sqlite3.h>
#include <time.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int mida_clear(void);
int mida_delete_with_pkgname(const char *pkg_name);
int mida_delete_with_mimetype(const char *mime_type);
int mida_add_app(const char *mime_type, const char *pkg_name);
char *mida_get_app(const char *mime_type);

int svc_clear(void);
int svc_delete_with_pkgname(const char *pkg_name);
int svc_delete_with_svcname(const char *svc_name);
int svc_add_app(const char *svc_name, const char *pkg_name);
char *svc_get_app(const char *svc_name);

int is_supported_svc(const char *svc_name);
#ifdef __cplusplus
}
#endif
#endif				/*__MIDA_H__ */

