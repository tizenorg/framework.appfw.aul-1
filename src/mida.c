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
#include <string.h>
#include <stdlib.h>
#include "mida.h"
#include "menu_db_util.h"
#include "simple_util.h"

#define MIDA_DB_PATH	"/opt/dbspace/.mida.db"
#define QUERY_MAXLEN	4096
#define BUF_MAX_LEN		1024

#define MIDA_TBL_NAME	"mida"
#define MIDA_F_PKGNAME	"pkg_name"
#define MIDA_F_MIMETYPE	"mime_type"

#define SVC_TBL_NAME	"svc"
#define SVC_F_PKGNAME	"pkg_name"
#define SVC_F_SVCNAME	"svc_name"

#define SYSSVC_TBL_NAME	"system_svc"
#define SYSSVC_F_SVCNAME "svc_name"

static sqlite3 *mida_db = NULL;


static int _exec(sqlite3 *db, char *query);
static int _init(void);
static int __fini(void);
static int __delete_all(const char *tbl_name);
static int __delete_with_field(const char *tbl_name, const char *f_name,
				const char *val, int equal);
static int __count_with_field(const char *tbl_name, const char *f_name,
				const char *val, int equal);
static char *__get_with_field(const char *tbl_name, const char *get_f_name, 
				const char *f_name, const char *val, int equal);
static int __doubt_sql_injection(const char *str);



/**
 * exec  
 * param[in] db handler
 * param[in] query query
 * return This method returns 0 (SUCCESS) or -1 (FAIL)
 */
static int _exec(sqlite3 *db, char *query)
{
	int rc = 0;
	char *errmsg = NULL;

	retvm_if(db == NULL, -1, "DB handler is null");

	rc = sqlite3_exec(db, query, NULL, 0, &errmsg);

	if (rc != SQLITE_OK) {
		_D("Query: [%s]", query);
		_E("SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		return (-1);
	}

	return 0;
}

/**
 * db initialize
 */
static int _init(void)
{
	int rc;

	if (mida_db) {
		_D("Already initialized\n");
		return 0;
	}

	rc = sqlite3_open(MIDA_DB_PATH, &mida_db);
	if (rc) {
		_E("Can't open database: %s", sqlite3_errmsg(mida_db));
		goto err;
	}
	/* Enable persist journal mode */
	rc = sqlite3_exec(mida_db, "PRAGMA journal_mode = PERSIST", NULL, NULL,
			  NULL);
	if (SQLITE_OK != rc) {
		_D("Fail to change journal mode\n");
		goto err;
	}

	return 0;
err:
	sqlite3_close(mida_db);
	return -1;
}

static int __fini(void)
{
	if (mida_db) {
		sqlite3_close(mida_db);
		mida_db = NULL;
	}
	return 0;
}

static int __delete_all(const char *tbl_name)
{
	char *_sqlbuf;
	int rc;

	_sqlbuf = sqlite3_mprintf("DELETE FROM %s;", tbl_name);
	rc = _exec(mida_db, _sqlbuf);
	sqlite3_free(_sqlbuf);

	return rc;
}

static int __delete_with_field(const char *tbl_name, const char *f_name,
			      const char *val, int equal)
{
	char tmp_val[BUF_MAX_LEN];
	char *_sqlbuf;
	int rc;

	if (equal) {
		_sqlbuf = sqlite3_mprintf("DELETE FROM %s WHERE %s = '%s';",
					  tbl_name, f_name, val);
	} else {
		snprintf(tmp_val, BUF_MAX_LEN, "%%%s%%", val);
		_sqlbuf = sqlite3_mprintf("DELETE FROM %s WHERE %s like '%s';",
					  tbl_name, f_name, tmp_val);
	}

	rc = _exec(mida_db, _sqlbuf);
	sqlite3_free(_sqlbuf);

	return rc;
}

static int __count_with_field(const char *tbl_name, const char *f_name,
			     const char *val, int equal)
{
	char tmp_val[BUF_MAX_LEN];
	char *_sqlbuf;
	int rc;
	char **db_result = NULL;
	char *db_err = NULL;
	int nrows = 0;
	int ncols = 0;
	int cnt;

	if (equal) {
		_sqlbuf = sqlite3_mprintf(
				"SELECT COUNT(*) FROM %s WHERE %s = '%s';",
				tbl_name, f_name, val);
	} else {
		snprintf(tmp_val, BUF_MAX_LEN, "%%%s%%", val);
		_sqlbuf = sqlite3_mprintf(
		"SELECT COUNT(*) FROM %s WHERE %s like '%s';", tbl_name,
		f_name, tmp_val);
	}

	rc = sqlite3_get_table(mida_db, _sqlbuf, &db_result, &nrows, &ncols,
			       &db_err);
	if (rc == -1 || nrows == 0) {
		_D("get count = 0 or fail");
		sqlite3_free_table(db_result);
		sqlite3_free(_sqlbuf);
		return 0;
	} else {
		cnt = atoi(db_result[1]);
		sqlite3_free_table(db_result);
		sqlite3_free(_sqlbuf);
	}

	return cnt;
}

static char *__get_with_field(const char *tbl_name, const char *get_f_name, 
			const char *f_name, const char *val, int equal)
{
	char tmp_val[BUF_MAX_LEN];
	char *_sqlbuf;
	sqlite3_stmt *stmt;
	int ret;
	char *res = NULL;

	if (equal) {
		_sqlbuf = sqlite3_mprintf("SELECT %s FROM %s WHERE %s = ?;",
					  get_f_name, tbl_name, f_name);

	} else {
		_sqlbuf = sqlite3_mprintf("SELECT %s FROM %s WHERE %s like ?;",
					  get_f_name, tbl_name, f_name);
	}
	if (_sqlbuf == NULL) {
		_D("Failed to print the SQL query\n");
		return res;
	}

	if (sqlite3_prepare_v2(mida_db, _sqlbuf, 
				-1, &stmt, NULL) != SQLITE_OK) {
		_D("Failed to prepare the SQL stmt\n");
		sqlite3_free(_sqlbuf);
		return res;
	}

	if (equal) {
		ret = sqlite3_bind_text(stmt, 1, val, -1, SQLITE_STATIC);
	} else {
		snprintf(tmp_val, BUF_MAX_LEN, "%%%s%%", val);
		ret = sqlite3_bind_text(stmt, 1, tmp_val, -1, SQLITE_STATIC);
	}
	if (ret != SQLITE_OK) {
		_D("Failed to bind %s with SQL stmt\n", val);
		goto end;
	}

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		if (sqlite3_column_text(stmt, 0)) {
			res = strdup((char *)sqlite3_column_text(stmt, 0));
		}
	}

end:
	sqlite3_finalize(stmt);
	sqlite3_free(_sqlbuf);
	return res;
}

static int __doubt_sql_injection(const char *str)
{
	char *tmp;
	char *token;
	char *saveptr;

	if (str == NULL)
		return 1;

	/* check " , ' , ; */
	tmp = strdup(str);
	token = strtok_r(tmp, "\"';", &saveptr);

	if (token == NULL)
		return 1;

	if (strcmp(str, token) != 0)
		return 1;

	free(tmp);

	return 0;
}

int mida_clear(void)
{
	int rc = 0;

	if (_init() < 0)
		return -1;
	rc = __delete_all(MIDA_TBL_NAME);
	__fini();

	return rc;
}

int mida_delete_with_pkgname(const char *pkg_name)
{
	int rc = 0;

	retvm_if(pkg_name == NULL, -1,
		 "Invalid argument: data to delete is NULL\n");

	if (_init() < 0)
		return -1;
	rc = __delete_with_field(MIDA_TBL_NAME, MIDA_F_PKGNAME, pkg_name, 1);
	__fini();

	return rc;
}

int mida_delete_with_mimetype(const char *mime_type)
{
	int rc = 0;

	retvm_if(mime_type == NULL, -1,
		 "Invalid argument: data to delete is NULL\n");

	if (_init() < 0)
		return -1;
	rc = __delete_with_field(MIDA_TBL_NAME, MIDA_F_MIMETYPE, mime_type, 0);
	__fini();

	return rc;
}

int mida_add_app(const char *mime_type, const char *pkg_name)
{
	int rc = -1;
	int cnt = 0;
	char *_sqlbuf;

	retvm_if(mime_type == NULL, -1, "Mime type is null\n");
	retvm_if(pkg_name == NULL, -1, "Package name is null\n");

	if (__doubt_sql_injection(mime_type))
		return -1;

	if (_init() < 0)
		return -1;

	cnt = __count_with_field(MIDA_TBL_NAME, MIDA_F_MIMETYPE, mime_type, 0);

	if (cnt == 0) {
		SECURE_LOGD("Inserting (%s, %s)", pkg_name, mime_type);
		/* insert */
		_sqlbuf = sqlite3_mprintf(
			    "INSERT INTO %s (%s,%s) values (\"%s\", \"%s\");",
			    MIDA_TBL_NAME, MIDA_F_PKGNAME, MIDA_F_MIMETYPE, 
			    pkg_name, mime_type);

		rc = _exec(mida_db, _sqlbuf);
		sqlite3_free(_sqlbuf);
	} else {
		SECURE_LOGD("Setting %s for %s", pkg_name, mime_type);
		/* update */
		_sqlbuf = sqlite3_mprintf(
				    "UPDATE %s SET %s = '%s' where %s = '%s';",
				    MIDA_TBL_NAME, MIDA_F_PKGNAME, pkg_name,
				    MIDA_F_MIMETYPE, mime_type);

		rc = _exec(mida_db, _sqlbuf);
		sqlite3_free(_sqlbuf);
	}

	if (rc < 0)
		_E("fail to insert or update\n");

	__fini();
	return rc;
}

char *mida_get_app(const char *mime_type)
{
	char *res = NULL;

	if (mime_type == NULL)
		return NULL;

	if (__doubt_sql_injection(mime_type))
		return NULL;

	if (_init() < 0)
		return NULL;
	res =
	    __get_with_field(MIDA_TBL_NAME, MIDA_F_PKGNAME, MIDA_F_MIMETYPE,
			    mime_type, 0);
	__fini();

	return res;
}

int svc_clear(void)
{
	int rc = 0;

	if (_init() < 0)
		return -1;
	rc = __delete_all(SVC_TBL_NAME);
	__fini();

	return rc;
}

int svc_delete_with_pkgname(const char *pkg_name)
{
	int rc = 0;

	retvm_if(pkg_name == NULL, -1,
		 "Invalid argument: data to delete is NULL\n");

	if (_init() < 0)
		return -1;
	rc = __delete_with_field(SVC_TBL_NAME, SVC_F_PKGNAME, pkg_name, 1);
	__fini();

	return rc;
}

int svc_delete_with_svcname(const char *svc_name)
{
	int rc = 0;

	retvm_if(svc_name == NULL, -1,
		 "Invalid argument: data to delete is NULL\n");

	if (_init() < 0)
		return -1;
	rc = __delete_with_field(SVC_TBL_NAME, SVC_F_SVCNAME, svc_name, 0);
	__fini();

	return rc;
}

int svc_add_app(const char *svc_name, const char *pkg_name)
{
	int rc = -1;
	int cnt = 0;
	char *_sqlbuf;

	retvm_if(svc_name == NULL, -1, "Service name is null\n");
	retvm_if(pkg_name == NULL, -1, "Package name is null\n");

	if (__doubt_sql_injection(svc_name))
		return -1;

	if (_init() < 0)
		return -1;

	cnt = __count_with_field(SVC_TBL_NAME, SVC_F_SVCNAME, svc_name, 0);

	if (cnt == 0) {
		/* insert */
		SECURE_LOGD("Inserting (%s, %s)", pkg_name, svc_name);
		_sqlbuf = sqlite3_mprintf(
		     "INSERT INTO %s (%s,%s) values (\"%s\", \"%s\");",
		     SVC_TBL_NAME, SVC_F_PKGNAME, SVC_F_SVCNAME, pkg_name,
		     svc_name);

		rc = _exec(mida_db, _sqlbuf);
		sqlite3_free(_sqlbuf);
	} else {
		/* update */
		SECURE_LOGD("Setting %s for %s", pkg_name, svc_name);
		_sqlbuf = sqlite3_mprintf(
				    "UPDATE %s SET %s = '%s' where %s = '%s';",
				    SVC_TBL_NAME, SVC_F_PKGNAME, pkg_name,
				    SVC_F_SVCNAME, svc_name);

		rc = _exec(mida_db, _sqlbuf);
		sqlite3_free(_sqlbuf);
	}

	if (rc < 0)
		_E("fail to insert or update\n");

	__fini();
	return rc;
}

char *svc_get_app(const char *svc_name)
{
	char *res = NULL;

	if (svc_name == NULL)
		return NULL;

	if (__doubt_sql_injection(svc_name))
		return NULL;

	if (_init() < 0)
		return NULL;
	res =
	    __get_with_field(SVC_TBL_NAME, SVC_F_PKGNAME, SVC_F_SVCNAME,
			    svc_name, 0);
	__fini();

	return res;
}

int is_supported_svc(const char *svc_name)
{
	int rc = 0;
	int cnt = 0;

	retvm_if(svc_name == NULL, 0, "Service name is null\n");

	if (__doubt_sql_injection(svc_name))
		return 0;

	if (_init() < 0)
		return 0;

	cnt = __count_with_field(SYSSVC_TBL_NAME, 
			SYSSVC_F_SVCNAME, svc_name, 0);

	if (cnt > 0)
		rc = 1;
	else
		SECURE_LOGD("%s is not supported.", svc_name);

	__fini();
	return rc;
}

