#include <stdio.h>
#include <stdlib.h>
#include "aul.h"

static void print_app_status(int status);

static void print_idle_info(void)
{
	int cnt = 0;
	int *pids = NULL;
	int i;
	char appid_buf[1024] = {0,};
	int ret;

	aul_app_group_get_idle_pids(&cnt, &pids);
	printf("< Idle : %d >\n", cnt);
	if (pids) {
		for (i = 0; i < cnt; ++i) {
			printf("---------------------------\n");
			printf("  pid : %d\n", pids[i]);
			ret = aul_app_get_appid_bypid(pids[i], appid_buf, sizeof(appid_buf) - 1);

			if (ret != AUL_R_OK) {
				appid_buf[0] = '\0';
			}
			printf("  appid : %s\n", appid_buf);
		}

		free(pids);
	}
}

static int print_info(void)
{
	int *leader_pids = NULL;
	int *member_pids = NULL;
	int group_cnt = 0;
	int member_cnt = 0;
	int win_id = 0;
	int group_num = 0;
	int member_num = 0;
	int app_status = -1;
	int ret = 0;
	char appid_buf[1024] = {0,};
	char pkgid_buf[1024] = {0,};
	int fg;

	aul_app_group_get_leader_pids(&group_cnt, &leader_pids);
	printf("App group count : %d\n", group_cnt);
	printf("\n");

	if(group_cnt == 0){
		printf("No app groups\n");
		goto FINISH;
	}

	for(group_num = 0; group_num < group_cnt; group_num++){
		aul_app_group_get_group_pids(leader_pids[group_num], &member_cnt, &member_pids);

		printf("< Group : %d >\n", group_num + 1);
		printf("member cnt : %d\n", member_cnt);
		printf("\n");

		for(member_num = 0; member_num < member_cnt; member_num++){
			ret = aul_app_get_appid_bypid(member_pids[member_num], appid_buf, sizeof(appid_buf) - 1);

			if(ret != AUL_R_OK){
				appid_buf[0] = '\0';
			}

			ret = aul_app_get_pkgid_bypid(member_pids[member_num], pkgid_buf, sizeof(pkgid_buf) - 1);
			if(ret != AUL_R_OK){
				pkgid_buf[0] = '\0';
			}

			win_id = aul_app_group_get_window(member_pids[member_num]);
			fg = aul_app_group_get_fg_flag(member_pids[member_num]);

			printf("--- member   : %d\n", member_num + 1);
			printf("  - app id   : %s\n", appid_buf);
			printf("  - pkg id   : %s\n", pkgid_buf);
			printf("  - pid      : %d\n", member_pids[member_num]);
			printf("  - win id   : %d\n", win_id);
			if (fg)
				printf("  - fg group : TRUE\n");
			else
				printf("  - fg group : FALSE\n");

			app_status = aul_app_get_status_bypid(member_pids[member_num]);
			print_app_status(app_status);
			printf("\n");
		}
		printf("==================================\n");
		printf("\n");
	}

FINISH:

	if(leader_pids != NULL)
		free(leader_pids);

	if(leader_pids != NULL)
		free(member_pids);

	return 0;
}

static void print_app_status(int status)
{
	switch (status) {
	case STATUS_LAUNCHING:
		printf("  - status   : STATUS_LAUNCHING \n");
		break;
	case STATUS_CREATED:
		printf("  - status   : STATUS_CREATED \n");
		break;
	case STATUS_FOCUS:
		printf("  - status   : STATUS_FOCUS \n");
		break;
	case STATUS_VISIBLE:
		printf("  - status   : STATUS_VISIBLE \n");
		break;
	case STATUS_BG:
		printf("  - status   : STATUS_BG \n");
		break;
	case STATUS_DYING:
		printf("  - status   : STATUS_DYING \n");
		break;
	case STATUS_HOME:
		printf("  - status   : STATUS_HOME \n");
		break;
	case STATUS_NORESTART:
		printf("  - status   : STATUS_NORESTART \n");
		break;
	default:
		printf("  - status error or unknown status\n");
		break;
	};
}

int main(int argc, char** argv)
{
	printf("\n");
	printf("### App Group Informantion ###\n");
	printf("\n");

	print_info();
	print_idle_info();

	printf("### end ###\n");

	return 0;
}
