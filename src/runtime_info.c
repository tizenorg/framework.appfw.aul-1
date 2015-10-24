/*
 *  aul
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <limits.h>

#include "aul.h"
#include "aul_api.h"
#include "simple_util.h"
#include "aul_zone.h"

#define _MAX_STATUS_BUF_SIZE	64
#define _MAX_STAT_BUF_SIZE		1024

static const char PROC_PROCESS_STATUS_INFO[] = "/proc/self/status";
static const char PROC_KEY_PROCESS_MEMORY[] = "VmSize";

long long __get_process_running_time(pid_t pid)
{
	char proc_path[_MAX_STAT_BUF_SIZE] = { 0, };
	char *line = NULL;
	ssize_t res = -1;
	int i = 0;
	char *str = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	long long start_time = 0;
	long long running_time = 0;

	if (pid == -1) //self
	{
		_D("self");
		snprintf(proc_path, sizeof(proc_path), "%sproc/self/stat", _get_root_path());
	}
	else if (pid > 0)
	{
		SECURE_LOGD("pid: %d", pid);
		snprintf(proc_path, sizeof(proc_path), "%sproc/%u/task", _get_root_path(), pid);
		_E("Not supported");
		return -1;
	}
	else
	{
		_E("PID is invalid.");
		return -1;
	}

	int fd = open(proc_path, O_RDONLY);
	if (fd < 0)
	{
		SECURE_LOGE("Openning %s is failed.", proc_path);
		goto CATCH;
	}

	line = (char *)calloc(_MAX_STAT_BUF_SIZE, sizeof(char));
	if (line == NULL)
	{
		_E("The memory is insufficient.");
		goto CATCH;
	}

	res = read(fd, line, _MAX_STAT_BUF_SIZE - 1);
	if (res < 0)
	{
		SECURE_LOGE("Reading %s is failed.", proc_path);
		goto CATCH;
	}
	close(fd);
	fd = -1;

	for (i = 0, str = line; ; ++i, str = NULL)
	{
		token = strtok_r(str, " ", &saveptr);
		if (token == NULL)
		{
			_E("There is no start time.");
			goto CATCH;
		}

		if (i == 21) //starttime
		{
			start_time = atoll(token);
			SECURE_LOGD("Start time: %lld (ticks)", start_time);
			break;
		}
	}
	free(line);
	line = NULL;

	{
		struct sysinfo info;
		sysinfo(&info);
		long long sec_since_boot = (long long)info.uptime;

		start_time /= (long long)sysconf(_SC_CLK_TCK);
		running_time = sec_since_boot - start_time;

		unsigned long mm = (unsigned long)running_time;
		unsigned ss = mm % 60;
		mm /= 60;
		SECURE_LOGD("Running time: %lu:%02u", mm, ss);
	}

	return running_time;

CATCH:
	if (fd >= 0)
	{
		close(fd);
	}
	if (line != NULL)
	{
		free(line);
	}

	return -1;
}

int __get_info_from_proc(const char* path, const char* key)
{
	int value = 0;

	char line[_MAX_STATUS_BUF_SIZE] = {0, };
	char field[_MAX_STATUS_BUF_SIZE] = {0, };

	FILE* fp = fopen(path, "r");
	if (fp != NULL)
	{
		while (fgets(line, _MAX_STATUS_BUF_SIZE, fp))
		{
			if (sscanf(line, "%s %d", field, &value) != EOF)
			{
				if (strncmp(field, key, strlen(key)) == 0)
				{
					if (value > (INT_MAX / 1024)) {
						value = INT_MAX / 1024;
					}

					SECURE_LOGD("PROC %s VALUE: %d\n", field, value * 1024);

					fclose(fp);

					return value * 1024;;
				}
			}
		}

		fclose(fp);
	}

	return -1;
}

SLPAPI int aul_get_app_allocated_memory(void)
{
	char buf[_MAX_STAT_BUF_SIZE] = {0, };

	snprintf(buf, _MAX_STAT_BUF_SIZE - 1, "%s%s", _get_root_path(),
	         PROC_PROCESS_STATUS_INFO);
	return __get_info_from_proc(buf, PROC_KEY_PROCESS_MEMORY);
}

SLPAPI long long aul_get_app_running_time(void)
{
	return __get_process_running_time(-1);
}
