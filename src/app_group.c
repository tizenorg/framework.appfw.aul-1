#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bundle_internal.h>
#include "aul.h"
#include "aul_api.h"
#include "aul_util.h"
#include "app_sock.h"
#include "launch.h"
#include "simple_util.h"

SLPAPI int aul_app_group_get_window(int pid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();
	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_GET_WINDOW, b);
	bundle_free(b);

	return ret;
}

SLPAPI int aul_app_group_set_window(int wid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();
	snprintf(buf, 128, "%d", wid);
	bundle_add_str(b, AUL_K_WID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_SET_WINDOW, b);
	bundle_free(b);

	return ret;
}

SLPAPI void aul_app_group_get_leader_pids(int *cnt, int **pids)
{
	app_pkt_t *ret = NULL;
	*cnt = 0;
	*pids = NULL;

	ret = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GROUP_GET_LEADER_PIDS,
			NULL, 0);
	if (ret != NULL) {
		*cnt = ret->len / sizeof(int);
		if (ret->len > 0 && ret->len <= AUL_SOCK_MAXBUFF - 8) {
			*pids = malloc(ret->len);
			if (*pids == NULL) {
				_E("out of memory");
				free(ret);
				return;
			}

			memcpy(*pids, ret->data, ret->len);
		}
		free(ret);
	}

}

SLPAPI void aul_app_group_get_group_pids(int leader_pid, int *cnt, int **pids)
{
	app_pkt_t *ret = NULL;
	bundle *b;
	bundle_raw *br;
	int datalen;
	char buf[128];
	*cnt = 0;
	*pids = NULL;

	b = bundle_create();
	snprintf(buf, 128, "%d", leader_pid);
	bundle_add_str(b, AUL_K_LEADER_PID, buf);

	bundle_encode(b, &br, &datalen);
	ret = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GROUP_GET_GROUP_PIDS, br,
			datalen);

	if (ret != NULL) {
		*cnt = ret->len / sizeof(int);
		if (ret->len > 0 && ret->len <= AUL_SOCK_MAXBUFF - 8) {
			*pids = malloc(ret->len);
			if (*pids == NULL) {
				_E("out of memory");
				free(br);
				bundle_free(b);
				free(ret);
				return;
			}

			memcpy(*pids, ret->data, ret->len);
		}
		free(ret);
	}

	free(br);
	bundle_free(b);
}

SLPAPI int aul_app_group_get_leader_pid(int pid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();
	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_GET_LEADER_PID, b);
	bundle_free(b);

	return ret;
}

SLPAPI int aul_app_group_clear_top(void)
{
	unsigned char dummy[1] = { 0 };
	return  __app_send_raw(AUL_UTIL_PID, APP_GROUP_CLEAR_TOP, dummy, 0);
}

SLPAPI int aul_app_group_is_top(void)
{
	int lpid = aul_app_group_get_leader_pid(getpid());

	if (lpid > 0) {
		int cnt;
		int *pids = NULL;
		aul_app_group_get_group_pids(lpid, &cnt, &pids);
		if (cnt > 0) {
			if (pids[cnt-1] == getpid()) {
				free(pids);
				return 1;
			}

			free(pids);
			return 0;
		}
	}

	return 1;
}

SLPAPI int aul_app_group_get_fg_flag(int pid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();
	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_GET_FG, b);
	bundle_free(b);

	return ret;
}

SLPAPI void aul_app_group_lower(int *exit)
{
	int ret;
	unsigned char dummy[1] = { 0 };
	ret =  __app_send_raw(AUL_UTIL_PID, APP_GROUP_LOWER, dummy, 0);
	*exit = ret;
}

SLPAPI void aul_app_group_get_idle_pids(int *cnt, int **pids)
{
	app_pkt_t *ret = NULL;
	*cnt = 0;
	*pids = NULL;

	ret = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GROUP_GET_IDLE_PIDS,
			NULL, 0);
	if (ret != NULL) {
		*cnt = ret->len / sizeof(int);
		if (ret->len > 0 && ret->len <= AUL_SOCK_MAXBUFF - 8) {
			*pids = malloc(ret->len);
			if (*pids == NULL) {
				_E("out of memory");
				free(ret);
				return;
			}

			memcpy(*pids, ret->data, ret->len);
		}
		free(ret);
	}
}

