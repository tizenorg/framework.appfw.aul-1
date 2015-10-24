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
#include "miregex.h"
#include "simple_util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MIREGEX_DIR SHARE_PREFIX"/miregex"
#define ONELINE_BUF 1024

typedef struct miregex_file_info_t {
	char *regex;
	char *desc;
} miregex_file_info;

regex_tbl *miregex_tbl = NULL;
static time_t miregex_mtime = 0;

static void __free_miregex_file_info(miregex_file_info *info);
static miregex_file_info *__get_miregex_file_info(const char *path);
static int __add_miregex(const char *name, const char *regex, const char *desc);
static int __need_update_miregex_tbl();
static void __miregex_free_regex_table();



static void __free_miregex_file_info(miregex_file_info *info)
{
	if (info == NULL)
		return;

	if (info->regex != NULL)
		free(info->regex);
	if (info->desc != NULL)
		free(info->desc);

	free(info);
}

static miregex_file_info *__get_miregex_file_info(const char *path)
{
	FILE *f;
	char oneline[ONELINE_BUF];
	miregex_file_info *info;

	f = fopen(path, "r");
	if (f == NULL) {
		_E("miregex file %s is cannot open", path);
		return NULL;
	}

	info = (miregex_file_info *) malloc(sizeof(miregex_file_info));
	if(info == NULL) {
		fclose(f);
		return NULL;
	}
		
	info->regex = NULL;
	info->desc = NULL;

	while ((info->regex == NULL) || (info->desc == NULL)) {
		memset(oneline, 0, ONELINE_BUF);
		if (fgets(oneline, ONELINE_BUF, f) == NULL)
			break;

		oneline[strlen(oneline) - 1] = 0;

		if (info->regex == NULL)
			info->regex = strdup(oneline);
		else
			info->desc = strdup(oneline);
	}

	/*_D("conf file process done : info->regex = %s, 
		info->desc = %s",info->regex, info->desc);*/
	fclose(f);

	return info;
}

static int __add_miregex(const char *name, const char *regex, const char *desc)
{
	regex_tbl *tbl = NULL;
	int error;
	int ret;
	char *msg = NULL;

	if (regex == NULL)
		return -1;

	tbl = (regex_tbl *) malloc(sizeof(regex_tbl));
	if (NULL == tbl) {
		_E("Malloc failed!");
		return -1;
	}

	if ((error = regcomp(&(tbl->regex_preg), regex,
			     REG_EXTENDED | REG_NOSUB)) != 0) {
		ret = regerror(error, &(tbl->regex_preg), NULL, 0);
		msg = (char *)malloc(sizeof(char) * ret);
		if (NULL == msg) {
			_E("Malloc failed!");
			if (tbl) {
				free(tbl);
				tbl = NULL;
			}
			return -1;
		}
		regerror(error, &(tbl->regex_preg), msg, ret);
		_E("regex compile error - %s\n", msg);
		if (msg) {
			free(msg);
			msg = NULL;
		}
		if (tbl) {
			free(tbl);
			tbl = NULL;
		}
		return -1;
	}

	tbl->mimetype = strdup(name);
	tbl->regex = strdup(regex);
	if (desc != NULL)
		tbl->desc = strdup(desc);
	tbl->next = miregex_tbl;
	miregex_tbl = tbl;

	/*_D("added regex - %d %s %s##",getpid(),tbl->mimetype,tbl->regex);*/

	return 0;
}

static int __need_update_miregex_tbl()
{
	struct stat st;

	if (stat(MIREGEX_DIR, &st) < 0) {
		_E("stat error - check miregex dir - %s", MIREGEX_DIR);
		return 1;
	}

	if (st.st_mtime != miregex_mtime) {
		miregex_mtime = st.st_mtime;
		return 1;
	}

	if (miregex_tbl == NULL) {
		miregex_mtime = st.st_mtime;
		return 1;
	}

	return 0;
}

static void __miregex_free_regex_table()
{
	regex_tbl *tbl;

	while (miregex_tbl) {
		if (miregex_tbl->mimetype != NULL)
			free(miregex_tbl->mimetype);
		if (miregex_tbl->regex != NULL)
			free(miregex_tbl->regex);
		if (miregex_tbl->desc != NULL)
			free(miregex_tbl->desc);
		regfree(&(miregex_tbl->regex_preg));

		tbl = miregex_tbl;
		miregex_tbl = miregex_tbl->next;
		free(tbl);
	}

	miregex_tbl = NULL;
}

regex_tbl *miregex_get_regex_table()
{
	DIR *dp;
	struct dirent dentry;
	struct dirent *result = NULL;
	char buf[MAX_LOCAL_BUFSZ];
	miregex_file_info *info;

	if (!__need_update_miregex_tbl())
		return miregex_tbl;

	_D("*** reload miregex tbl ***");

	if (miregex_tbl != NULL)
		__miregex_free_regex_table();

	dp = opendir(MIREGEX_DIR);
	if (dp == NULL)
		return NULL;

	while (readdir_r(dp, &dentry, &result) == 0 && result != NULL) {
		if (dentry.d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", MIREGEX_DIR,
			 dentry.d_name);
		info = __get_miregex_file_info(buf);
		if (info == NULL)
			continue;

		if (__add_miregex(dentry.d_name,
			info->regex, info->desc) < 0) {
			/* TODO : invalid regular expression - will be removed*/
		}

		__free_miregex_file_info(info);
	}

	closedir(dp);

	return miregex_tbl;
}

