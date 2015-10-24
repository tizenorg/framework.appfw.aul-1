/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib/gstdio.h>
#include <bundle_internal.h>
#include <assert.h>
#include <dlog.h>
#include <vconf.h>
#include <system_info.h>
#include <pkgmgr-info.h>
#include <pkgmgrinfo_resource.h>

#include "aul.h"
#include "aul_api.h"
#include "aul_rsc_mgr.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "AUL_RESOURCE_MANAGER"

#define WEIGHT_SCREEN_DPI 10000
#define WEIGHT_SCREEN_DPI_RANGE 10000
#define WEIGHT_SCREEN_BPP 1000
#define WEIGHT_SCREEN_WIDTH_RANGE 100
#define WEIGHT_SCREEN_LARGE 10
#define WEIGHT_PLATFORM_VERSION 1000000
#define WEIGHT_LANGUAGE 100000

#define THRESHOLD_TO_CLEAN 50	/* app_resource_manager_trim_cache */

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
#define MAX_PATH  1024

typedef struct {
	resource_data_t *data;
	GHashTable *cache;
} resource_manager_t;

typedef struct {
	char *output;
	int hit_cnt;
	bool remove;
} resource_cache_context_t;

typedef struct {
	const char *bundle_attr_key;
	unsigned int bundle_attr_value;
} resource_node_attr_t;

typedef struct {
	char *folder;
	char *type;
} resource_node_list_t;

enum {
	NODE_ATTR_MIN = 0,
	NODE_ATTR_SCREEN_DPI,
	NODE_ATTR_SCREEN_DPI_RANGE,
	NODE_ATTR_SCREEN_WIDTH_RANGE,
	NODE_ATTR_SCREEN_LARGE,
	NODE_ATTR_SCREEN_BPP,
	NODE_ATTR_PLATFORM_VER,
	NODE_ATTR_LANGUAGE,
	NODE_ATTR_MAX
};

static resource_manager_t *resource_handle = NULL;

static resource_node_attr_t map[] = {
		{ RSC_NODE_ATTR_SCREEN_DPI, NODE_ATTR_SCREEN_DPI },
		{ RSC_NODE_ATTR_SCREEN_DPI_RANGE, NODE_ATTR_SCREEN_DPI_RANGE },
		{ RSC_NODE_ATTR_SCREEN_WIDTH_RANGE, NODE_ATTR_SCREEN_WIDTH_RANGE },
		{ RSC_NODE_ATTR_SCREEN_LARGE, NODE_ATTR_SCREEN_LARGE },
		{ RSC_NODE_ATTR_SCREEN_BPP, NODE_ATTR_SCREEN_BPP },
		{ RSC_NODE_ATTR_PLATFORM_VER, NODE_ATTR_PLATFORM_VER },
		{ RSC_NODE_ATTR_LANGUAGE, NODE_ATTR_LANGUAGE },
};

static GHashTable *attr_key = NULL;
static const char *res_path = NULL;
static char *cur_language = NULL;
static bool is_slice = FALSE;

static GHashTable *valid_path_list = NULL;
static GHashTable *supported_lang_list = NULL;
static GHashTable *id_list = NULL;
static GList *all_node_list = NULL;
static bundle *given_attr_list = NULL;

static gint __resource_manager_comp(gconstpointer a, gconstpointer b)
{
	resource_group_t *rsc_group = (resource_group_t *) a;

	return strcmp(rsc_group->type, b);
}

static gint __compare_path(gconstpointer a, gconstpointer b)
{
	char tmp_path[MAX_PATH] = {0, };
	resource_node_list_t *tmp_node_info= (resource_node_list_t *)a;

	snprintf(tmp_path, MAX_PATH - 1, "%s%s", res_path, tmp_node_info->folder);
	return strncmp(tmp_path, (char *)b, strlen(tmp_path));
}


static int __get_dpi(void)
{
	int dpi = 0;
	char *tmp = NULL;
	if (is_slice) {
		bundle_get_str(given_attr_list, RSC_NODE_ATTR_SCREEN_DPI, &tmp);
		if (tmp == NULL) {
			LOGE("Failed to retrieve DPI");
			dpi = 0;
		} else
			dpi = atoi(tmp);
	} else
		system_info_get_platform_int("http://tizen.org/feature/screen.dpi", &dpi);

	return dpi;
}

static int __get_screen_width(void)
{
	int screen_width = 0;
	char *tmp = NULL;

	if (is_slice) {
		bundle_get_str(given_attr_list, RSC_NODE_ATTR_SCREEN_WIDTH_RANGE, &tmp);
		if (tmp == NULL) {
			LOGE("Failed to retrieve screen width");
			screen_width = 0;
		} else
			screen_width = atoi(tmp);
	} else
		system_info_get_platform_int("http://tizen.org/feature/screen.width", &screen_width);

	return screen_width;
}

static bool __get_screen_large(void)
{
	bool screen_large = true;
	char *tmp = NULL;

	if (is_slice) {
		bundle_get_str(given_attr_list, RSC_NODE_ATTR_SCREEN_LARGE, &tmp);
		if (tmp == NULL) {
			LOGE("Failed to retrieve screen large");
			screen_large = false;
		} else
			screen_large = atoi(tmp);
	} else {
		if (system_info_get_platform_bool("http://tizen.org/feature/screen.size.large", &screen_large) != SYSTEM_INFO_ERROR_NONE) {
			LOGE("Failed to get info of screen.size.large");
			screen_large = false;
		}
	}

	return screen_large;
}

static int __get_screen_bpp(void)
{
	int screen_bpp = 0;
	char *tmp = NULL;

	if (is_slice) {
		bundle_get_str(given_attr_list, RSC_NODE_ATTR_SCREEN_BPP, &tmp);
		if (tmp == NULL) {
			LOGE("Failed to retrieve screen bpp");
			screen_bpp = 0;
		} else
			screen_bpp = atoi(tmp);
	} else
		system_info_get_platform_int("http://tizen.org/feature/screen.bpp", &screen_bpp);

	return screen_bpp;
}

static char *__get_platform_version(void)
{
	char *version = NULL;
	if (is_slice)
		bundle_get_str(given_attr_list, RSC_NODE_ATTR_PLATFORM_VER, &version);
	else
		system_info_get_platform_string("http://tizen.org/feature/platform.version", &version);

	return version;
}

static void __bundle_iterator_get_valid_nodes(const char *key, const int type,
		const bundle_keyval_t *kv, void *data)
{
	unsigned int node_attr;
	bool *invalid = (bool *) data;
	bool ret_bool = true;
	int min, max;
	char from[5] = { 0, };
	char to[3] = { 0, };
	bool t_val;
	char *val;
	size_t size;
	static int screen_dpi = -1;
	static int screen_width = -1;
	static int screen_size_large = -1;
	static char *version = NULL;
	static int screen_bpp = -1;

	if (*invalid)
		return;

	bundle_keyval_get_basic_val((bundle_keyval_t *) kv, (void**) &val, &size);

	node_attr = (guint) g_hash_table_lookup(attr_key, key);
	if (node_attr <= NODE_ATTR_MIN || node_attr >= NODE_ATTR_MAX) {
		LOGE("INVALID_PARAMETER(0x%08x), node_attr(%d)",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER, node_attr);
		*invalid = true;
		return;
	}

	switch (node_attr) {
		case NODE_ATTR_SCREEN_DPI:
			if (screen_dpi == -1)
				screen_dpi =__get_dpi();
			if (screen_dpi != atoi(val))
				*invalid = true;
			break;

		case NODE_ATTR_SCREEN_DPI_RANGE:
			sscanf(val, "%s %d %s %d", from, &min, to, &max);
			if (screen_dpi == -1)
				screen_dpi =__get_dpi();
			if (!(min <= screen_dpi && screen_dpi <= max))
				*invalid = true;
			break;

		case NODE_ATTR_SCREEN_WIDTH_RANGE:
			sscanf(val, "%s %d %s %d", from, &min, to, &max);
			if (screen_width == -1)
				screen_width = __get_screen_width();
			if (!(min <= screen_width && screen_width <= max))
				*invalid = true;
			break;

		case NODE_ATTR_SCREEN_LARGE:
			if (!(strcmp(val, "true")))
				t_val = true;
			else
				t_val = false;
			if (screen_size_large == -1) {
				ret_bool = __get_screen_large();
				if (ret_bool)
					screen_size_large = 1;
				else
					screen_size_large = 0;
			}
			if (((bool)screen_size_large) != t_val)
				*invalid = true;
			break;

		case NODE_ATTR_SCREEN_BPP:
			if (screen_bpp == -1)
				screen_bpp = __get_screen_bpp();
			if (screen_bpp != atoi(val))
				*invalid = true;
			break;

		case NODE_ATTR_PLATFORM_VER:
			if (version == NULL)
				version = __get_platform_version();
			if (strcmp(version, val))
				*invalid = true;
			break;

		case NODE_ATTR_LANGUAGE:
			if (cur_language == NULL)
					cur_language = vconf_get_str(VCONFKEY_LANGSET);

			if (strncmp(cur_language, val, strlen(val)))
				*invalid = true;
			break;
	}
}

static void __bundle_iterator_get_best_node(const char *key, const char *val,
		void *data)
{
	unsigned int node_attr;
	unsigned int *weight = (unsigned int *) data;

	node_attr = (guint) g_hash_table_lookup(attr_key, key);
	if (node_attr <= NODE_ATTR_MIN || node_attr >= NODE_ATTR_MAX) {
		LOGE("INVALID_PARAMETER(0x%08x), node_attr(%d)",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER, node_attr);
		return;
	}

	switch (node_attr) {
		case NODE_ATTR_SCREEN_DPI:
			*weight += WEIGHT_SCREEN_DPI;
			break;

		case NODE_ATTR_SCREEN_DPI_RANGE:
			*weight += WEIGHT_SCREEN_DPI_RANGE;
			break;

		case NODE_ATTR_SCREEN_WIDTH_RANGE:
			*weight += WEIGHT_SCREEN_WIDTH_RANGE;
			break;

		case NODE_ATTR_SCREEN_LARGE:
			*weight += WEIGHT_SCREEN_LARGE;
			break;

		case NODE_ATTR_SCREEN_BPP:
			*weight += WEIGHT_SCREEN_BPP;
			break;

		case NODE_ATTR_PLATFORM_VER:
			*weight += WEIGHT_PLATFORM_VERSION;
			break;

		case NODE_ATTR_LANGUAGE:
			*weight += WEIGHT_LANGUAGE;
			break;
	}
}

static const char *__get_cache(aul_resource_e type,
		const char *id)
{
	unsigned int total_len = 0;
	char *key = NULL;
	char *rsc_type;
	resource_cache_context_t *resource_cache = NULL;

	if (is_slice == TRUE)
		return NULL;

	if (id == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), id",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return NULL;
	}

	if (type < AUL_RESOURCE_TYPE_MIN || type > AUL_RESOURCE_TYPE_MAX) {
		LOGE("INVALID_PARAMETER(0x%08x), type(%d)",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER, type);
		return NULL;
	} else {
		switch (type) {
			case AUL_RESOURCE_TYPE_IMAGE:
				rsc_type = RSC_GROUP_TYPE_IMAGE;
				break;

			case AUL_RESOURCE_TYPE_LAYOUT:
				rsc_type = RSC_GROUP_TYPE_LAYOUT;
				break;

			case AUL_RESOURCE_TYPE_SOUND:
				rsc_type = RSC_GROUP_TYPE_SOUND;
				break;

			case AUL_RESOURCE_TYPE_BIN:
				rsc_type = RSC_GROUP_TYPE_BIN;
				break;
		}
	}

	if (resource_handle->cache == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), hashtable",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return NULL;
	} else {
		total_len = strlen(rsc_type) + strlen(id) + 2;

		key = (char *) calloc(1, total_len);
		if (key == NULL) {
			LOGE("failed to create a resource_cache(0x%08x)",
					AUL_RESOURCE_ERROR_OUT_OF_MEMORY);
			free(resource_cache);
			return NULL;
		}

		snprintf(key, total_len, "%s:%s", rsc_type, id);
		LOGD("key : %s", key);

		resource_cache = g_hash_table_lookup(resource_handle->cache, key);
		free(key);
		if (resource_cache == NULL) {
			LOGE("IO_ERROR(0x%08x), find list resource_cache",
					AUL_RESOURCE_ERROR_IO_ERROR);
			return NULL;
		}

		resource_cache->hit_cnt++;
	}

	return resource_cache->output;
}

static gint __cache_hit_compare(gconstpointer a, gconstpointer b)
{
	const resource_cache_context_t *lhs = (const resource_cache_context_t *) a;
	const resource_cache_context_t *rhs = (const resource_cache_context_t *) b;

	return lhs->hit_cnt - rhs->hit_cnt;
}

static gboolean __cache_remove(gpointer key, gpointer value, gpointer user_data)
{
	resource_cache_context_t *c = (resource_cache_context_t *) (value);

	if (c->remove) {
		free(key);
		free(c->output);
		free(c);
		return TRUE;
	}

	return FALSE;
}

static void __trim_cache(void)
{
	GList *values = g_hash_table_get_values(resource_handle->cache);
	values = g_list_sort(values, __cache_hit_compare);

	int i = 0;
	GList *iter_list = values;
	while (iter_list != NULL) {
		if (i >= (THRESHOLD_TO_CLEAN / 2))
			break;

		resource_cache_context_t *c =
				(resource_cache_context_t *) (iter_list->data);
		c->remove = true;
		iter_list = g_list_next(iter_list);
		i++;
	}

	g_list_free(values);
	g_hash_table_foreach_remove(resource_handle->cache, __cache_remove, NULL);

}

static void __put_cache(aul_resource_e type, const char *id,
		const char *val)
{
	unsigned int total_len = 0;
	char *key;
	char *rsc_type;
	resource_cache_context_t *resource_cache;

	if (is_slice == TRUE)
		return;

	/* To remove chache from the low frequency of use. */
	if (val == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), fname",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return;
	}

	if (id == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), id",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return;
	}

	if (type < AUL_RESOURCE_TYPE_MIN || type > AUL_RESOURCE_TYPE_MAX) {
		LOGE("INVALID_PARAMETER(0x%08x), type(%d)",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER, type);
		return;
	} else {
		switch (type) {
			case AUL_RESOURCE_TYPE_IMAGE:
				rsc_type = RSC_GROUP_TYPE_IMAGE;
				break;

			case AUL_RESOURCE_TYPE_LAYOUT:
				rsc_type = RSC_GROUP_TYPE_LAYOUT;
				break;

			case AUL_RESOURCE_TYPE_SOUND:
				rsc_type = RSC_GROUP_TYPE_SOUND;
				break;

			case AUL_RESOURCE_TYPE_BIN:
				rsc_type = RSC_GROUP_TYPE_BIN;
				break;
		}
	}

	if (g_hash_table_size(resource_handle->cache) > THRESHOLD_TO_CLEAN)
		__trim_cache();

	resource_cache = (resource_cache_context_t *) calloc(1,
			sizeof(resource_cache_context_t));
	if (resource_cache == NULL) {
		LOGE("failed to create a resource_group(0x%08x)",
				AUL_RESOURCE_ERROR_OUT_OF_MEMORY);
		return;
	}

	total_len = strlen(rsc_type) + strlen(id) + 2;

	key = (char *) calloc(1, total_len);
	if (key == NULL) {
		LOGE("failed to create a resource_cache(0x%08x)",
				AUL_RESOURCE_ERROR_OUT_OF_MEMORY);
		free(resource_cache);
		return;
	}

	snprintf(key, total_len, "%s:%s", rsc_type, id);
	LOGD("key : %s", key);

	resource_cache->output = strdup(val);
	resource_cache->hit_cnt = 0;
	resource_cache->remove = false;

	g_hash_table_insert(resource_handle->cache, key, resource_cache);
}

static resource_group_t *__find_group(resource_data_t *data,
		int type)
{
	resource_group_t *rsc_group = NULL;
	char *rsc_type;

	if (data == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), resource_data_t",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return NULL;
	}

	if (type < AUL_RESOURCE_TYPE_MIN || type > AUL_RESOURCE_TYPE_MAX) {
		LOGE("INVALID_PARAMETER(0x%08x), type(%d)",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER, type);
		return NULL;
	} else {
		switch (type) {
			case AUL_RESOURCE_TYPE_IMAGE:
				rsc_type = RSC_GROUP_TYPE_IMAGE;
				break;

			case AUL_RESOURCE_TYPE_LAYOUT:
				rsc_type = RSC_GROUP_TYPE_LAYOUT;
				break;

			case AUL_RESOURCE_TYPE_SOUND:
				rsc_type = RSC_GROUP_TYPE_SOUND;
				break;

			case AUL_RESOURCE_TYPE_BIN:
				rsc_type = RSC_GROUP_TYPE_BIN;
				break;
		}
	}

	GList* found = g_list_find_custom(data->group_list, rsc_type,
			__resource_manager_comp);
	if (found == NULL) {
		LOGE("IO_ERROR(0x%08x), find list resource_group %s",
				AUL_RESOURCE_ERROR_IO_ERROR, rsc_type);
		return NULL;
	}

	rsc_group = (resource_group_t *) (found->data);

	return rsc_group;
}

static GList *__get_valid_nodes(resource_group_t *group,
		const char *id)
{
	GList *list = NULL;
	GList *valid_list = NULL;
	resource_node_t *valid_node = NULL;
	resource_node_t *rsc_node = NULL;

	if (group->node_list == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), resource_group",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return NULL;
	}

	list = g_list_first(group->node_list);

	char path_buf[MAX_PATH] = { 0, };
	while (list) {
		bool invalid = false;
		rsc_node = (resource_node_t *) list->data;

		snprintf(path_buf, MAX_PATH - 1, "%s%s/%s", res_path,
				rsc_node->folder, id);
		if (access(path_buf, R_OK) == 0) {
			bundle_foreach(rsc_node->attr, __bundle_iterator_get_valid_nodes,
					&invalid);

			if (!invalid) {
				valid_node = (resource_node_t *) list->data;
				valid_list = g_list_append(valid_list, valid_node);
			}
		}

		list = g_list_next(list);
	}

	return valid_list;
}

static resource_node_t *__get_best_node(GList *nodes)
{
	unsigned int weight_tmp = 0;
	resource_node_t *best_node = NULL;
	GList *list = NULL;

	if (nodes == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), resource_node lists",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return NULL;
	}

	list = g_list_first(nodes);

	while (list != NULL) {
		unsigned int weight = 0;
		resource_node_t *res_node = (resource_node_t *) (list->data);

		bundle_iterate(res_node->attr, __bundle_iterator_get_best_node, &weight);
		if (weight > weight_tmp) {
			best_node = res_node;
			weight_tmp = weight;
		}
		list = g_list_next(list);
	}

	return best_node;
}

static int __open(resource_manager_t **handle)
{
	int retval = AUL_RESOURCE_ERROR_NONE;
	resource_manager_t *rsc_manager = NULL;
	char buf[MAX_PATH] = { 0, };

	rsc_manager = (resource_manager_t *) calloc(1, sizeof(resource_manager_t));
	if (!rsc_manager) {
		LOGE("failed to create a resource_manager(0x%08x)",
				AUL_RESOURCE_ERROR_OUT_OF_MEMORY);
		return AUL_RESOURCE_ERROR_OUT_OF_MEMORY;
	}

	snprintf(buf, MAX_PATH - 1, "%sres.xml", res_path);
	retval = pkgmgrinfo_resource_open(buf, &(rsc_manager->data));
	if (retval != PMINFO_R_OK) {
		LOGE("IO_ERROR(0x%08x), failed to get db for resource manager",
				AUL_RESOURCE_ERROR_IO_ERROR);
		free(rsc_manager);
		return AUL_RESOURCE_ERROR_IO_ERROR;
	}

	rsc_manager->cache = g_hash_table_new(g_str_hash, g_str_equal);
	*handle = rsc_manager;

	return AUL_RESOURCE_ERROR_NONE;
}

static void __invalidate_cache()
{
	if (resource_handle != NULL) {
		if (resource_handle->cache != NULL) {
			GHashTableIter iter;
			gpointer key, value;

			g_hash_table_iter_init(&iter, resource_handle->cache);
			while (g_hash_table_iter_next(&iter, &key, &value)) {
				free(key);
				resource_cache_context_t *c = (resource_cache_context_t *) value;
				free(c->output);
				free(value);
			}
			g_hash_table_remove_all(resource_handle->cache);
			if (cur_language) {
				free(cur_language);
				cur_language = NULL;
			}
		}
	}
}

static int __close(resource_manager_t *handle)
{
	if (handle == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), resource_manager",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return AUL_RESOURCE_ERROR_INVALID_PARAMETER;
	}

	__invalidate_cache();
	if (handle->cache != NULL) {
		g_hash_table_destroy(handle->cache);
	}

	if (handle->data != NULL) {
		pkgmgrinfo_resource_close(handle->data);
	}

	free(handle);

	return AUL_RESOURCE_ERROR_NONE;
}

static void __vconf_cb(keynode_t *key, void *data)
{
	__invalidate_cache();
}

static const char *_get_app_resource_path(const char *rsc_folder_path)
{
	if (is_slice == FALSE)
		return aul_get_app_resource_path();

	if (rsc_folder_path == NULL)
		return NULL;

	return rsc_folder_path;
}

static void path_callback(char *path)
{
	char orig_path[MAX_PATH] = {0, };
	char *path_ptr = NULL;
	int path_len = 0;
	GList *tmp_list = g_list_find_custom(all_node_list, path, __compare_path);

	resource_node_list_t *tmp_node_info = NULL;
	if (tmp_list == NULL)
		g_hash_table_add(valid_path_list, strdup(path));
	else {
		tmp_node_info = (resource_node_list_t *)tmp_list->data;
		path_len = strlen(path);
		if (path_len >= MAX_PATH) {
			LOGE("path[%s] is too long", path);
			return;
		}
		strncpy(orig_path, path, path_len);
		path_ptr = &orig_path[strlen(res_path) + strlen(tmp_node_info->folder)];
		g_hash_table_insert(id_list, strdup(path_ptr), strdup(tmp_node_info->type));
	}
}

static void __scan_dir(const char *path, void (*func)(char *))
{
	struct dirent **items;
	int nitems, i;
	struct stat fstat;
	char abs_path[MAX_PATH] = {0, };
	char cwd[MAX_PATH] = {0, };
	char *tmp = NULL;

	if (chdir(path) < 0) {
		LOGE("failed to chdir[%s]", path);
		return;
	}

	tmp = getcwd(cwd, MAX_PATH - 1);
	if (tmp == NULL) {
		LOGE("failed to get cwd");
		return;
	}
	nitems = scandir("./", &items, NULL, alphasort);

	for (i = 0; i < nitems; i++) {
		if (items[i]->d_name[0] == '.')
			continue;

		snprintf(abs_path, MAX_PATH - 1, "%s/%s", cwd, items[i]->d_name);

		if (g_lstat(abs_path, &fstat) != 0) {
			LOGE("failed to retrieve info[%s]", abs_path);
			return;
		}
		if ((fstat.st_mode & S_IFDIR) == S_IFDIR)
			__scan_dir(abs_path, path_callback);
		else
			func(abs_path);
	}

}

static aul_resource_e __get_resource_type(char *type)
{
	if (type == NULL)
		return -1;

	if (strcmp(type, RSC_GROUP_TYPE_IMAGE) == 0)
		return AUL_RESOURCE_TYPE_IMAGE;
	else if(strcmp(type, RSC_GROUP_TYPE_LAYOUT) == 0)
		return AUL_RESOURCE_TYPE_LAYOUT;
	else if(strcmp(type, RSC_GROUP_TYPE_SOUND) == 0)
		return AUL_RESOURCE_TYPE_SOUND;
	else if(strcmp(type, RSC_GROUP_TYPE_BIN) == 0)
		return AUL_RESOURCE_TYPE_BIN;
	else
		return -1;
}

static int __set_valid_filelist(bundle *b)
{
	if (b == NULL || supported_lang_list == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), bundle",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return AUL_RESOURCE_ERROR_INVALID_PARAMETER;
	}

	int retval = AUL_RESOURCE_ERROR_NONE;
	char *path = NULL;
	GHashTableIter id_list_iter;
	GHashTableIter lang_list_iter;
	gpointer id_key, lang_key, id_type;
	aul_resource_e rsc_type = AUL_RESOURCE_TYPE_MIN;

	given_attr_list = b;
	g_hash_table_iter_init(&id_list_iter, id_list);

	while (g_hash_table_iter_next(&id_list_iter, &id_key, &id_type)) {
		rsc_type = __get_resource_type((char *)id_type);
		if (rsc_type == -1) {
			LOGE("failed to get resource type[%s]", (char *)id_type);
			return AUL_RESOURCE_ERROR_IO_ERROR;
		}

		g_hash_table_iter_init(&lang_list_iter, supported_lang_list);
		while (g_hash_table_iter_next(&lang_list_iter, &lang_key, NULL)) {
			cur_language = strdup(lang_key);
			if (cur_language == NULL) {
				LOGE("failed to strdup");
				return AUL_RESOURCE_ERROR_OUT_OF_MEMORY;
			}

			retval = aul_resource_manager_get(rsc_type, id_key, &path);
			if (retval == AUL_RESOURCE_ERROR_NONE)
				g_hash_table_add(valid_path_list, path);
			else
				LOGE("failed to get value with given type[%d], key[%s]", rsc_type, id_key);

			if (cur_language) {
				free(cur_language);
				cur_language = NULL;
			}
		}
	}
	return AUL_RESOURCE_ERROR_NONE;
}

static int __make_list(void)
{
	resource_group_t *tmp_group = NULL;
	resource_node_t  *tmp_node = NULL;
	resource_node_list_t *tmp_node_struct = NULL;
	char *group_type = NULL;
	char folder[MAX_PATH] = {0 ,};
	char *node_lang = NULL;
	GList *group_list = NULL;
	GList *node_list = NULL;
	bundle *b = NULL;


	/* make node folder list */
	group_list = resource_handle->data->group_list;
	if (group_list == NULL)
		return AUL_RESOURCE_ERROR_IO_ERROR;

	while (group_list != NULL) {
		tmp_group = (resource_group_t *)group_list->data;
		if (tmp_group == NULL)
			return AUL_RESOURCE_ERROR_IO_ERROR;

		group_type = tmp_group->type;
		node_list = tmp_group->node_list;
		memset(folder, '\0', MAX_PATH);
		snprintf(folder, MAX_PATH - 1, "%s/",tmp_group->folder);

		/*make struct and put it into all node list*/
		tmp_node_struct = (resource_node_list_t *)calloc(1, sizeof(resource_node_list_t));
		if (tmp_node_struct == NULL) {
			LOGE("calloc failed");
			return AUL_RESOURCE_ERROR_OUT_OF_MEMORY;
		}

		tmp_node_struct->folder = strdup(folder);
		tmp_node_struct->type = strdup(group_type);
		all_node_list = g_list_append(all_node_list, tmp_node_struct);

		while (node_list != NULL) {
			tmp_node = (resource_node_t *)node_list->data;
			if (tmp_node == NULL)
				return AUL_RESOURCE_ERROR_IO_ERROR;

			/*retrieve language value from each node*/
			b = tmp_node->attr;
			if (b == NULL)
				return AUL_RESOURCE_ERROR_IO_ERROR;
			bundle_get_str(b, RSC_NODE_ATTR_LANGUAGE, &node_lang);
			if (node_lang != NULL)
				g_hash_table_add(supported_lang_list, strdup(node_lang));

			memset(folder, '\0', MAX_PATH);
			snprintf(folder, MAX_PATH - 1, "%s/",tmp_node->folder);

			/*make struct and put it into all node list*/
			tmp_node_struct = (resource_node_list_t *)calloc(1, sizeof(resource_node_list_t));
			if (tmp_node_struct == NULL) {
				LOGE("calloc failed");
				return AUL_RESOURCE_ERROR_OUT_OF_MEMORY;
			}

			tmp_node_struct->folder = strdup(folder);
			tmp_node_struct->type = strdup(group_type);
			all_node_list = g_list_prepend(all_node_list, tmp_node_struct);

			node_list = g_list_next(node_list);
		}
		group_list = g_list_next(group_list);
	}

	__scan_dir(res_path, path_callback);

	/* add language which is not existed to find default resources */
	g_hash_table_add(supported_lang_list, strdup("NoLang"));
	return AUL_RESOURCE_ERROR_NONE;
}

static void __free_str(gpointer data)
{
	if (data == NULL)
		return;

	char *char_data = (char *)data;
	free(char_data);
	data = NULL;
}

static int __init(const char *rsc_folder_path, bundle *b)
{
	if (rsc_folder_path != NULL && b != NULL)
		is_slice = TRUE;
	else
		is_slice = FALSE;

	if (resource_handle != NULL)
		return AUL_RESOURCE_ERROR_NONE;

	int retval = AUL_RESOURCE_ERROR_NONE;

	res_path = _get_app_resource_path(rsc_folder_path);
	if (res_path == NULL) {
		LOGE("IO_ERROR(0x%08x), failed to get resource path",
				AUL_RESOURCE_ERROR_IO_ERROR);
		return AUL_RESOURCE_ERROR_IO_ERROR;
	}

	retval = __open(&resource_handle);
	if (retval != AUL_RESOURCE_ERROR_NONE) {
		LOGE("IO_ERROR(0x%08x), failed to get resource_handle(%d)",
				AUL_RESOURCE_ERROR_IO_ERROR, retval);
		return AUL_RESOURCE_ERROR_IO_ERROR;
	}

	if (attr_key == NULL) {
		attr_key = g_hash_table_new(g_str_hash, g_str_equal);

		if (attr_key == NULL)
			return AUL_RESOURCE_ERROR_OUT_OF_MEMORY;

		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(map); i++) {
			g_hash_table_insert(attr_key, (char *) map[i].bundle_attr_key,
					(gpointer) (map[i].bundle_attr_value));
		}
	}

	if (is_slice == FALSE) {
		int r = vconf_notify_key_changed(VCONFKEY_LANGSET, __vconf_cb, NULL);

		if (r < 0) {
			LOGE("IO_ERROR(0x%08x), failed to register vconf(%d)",
					AUL_RESOURCE_ERROR_IO_ERROR, r);
			return AUL_RESOURCE_ERROR_IO_ERROR;
		}
	} else {
		/* make ID list */
		if (id_list == NULL)
			id_list = g_hash_table_new_full(g_str_hash, g_str_equal, __free_str, __free_str);

		if (supported_lang_list == NULL)
			supported_lang_list = g_hash_table_new_full(g_str_hash, g_str_equal, __free_str, NULL);

		if (valid_path_list == NULL)
			valid_path_list = g_hash_table_new_full(g_str_hash, g_str_equal, __free_str, NULL);

		retval = __make_list();
		if (retval < 0) {
			LOGE("Failed to initialize filelist");
			return AUL_RESOURCE_ERROR_IO_ERROR;
		}

		retval = __set_valid_filelist(b);
		if (retval < 0) {
			LOGE("Failed to get valid filelist");
			return AUL_RESOURCE_ERROR_IO_ERROR;
		}

	}

	return AUL_RESOURCE_ERROR_NONE;
}

SLPAPI int aul_resource_manager_init(void)
{
	return __init(NULL, NULL);
}

SLPAPI int aul_resource_manager_init_slice(const char *rsc_folder_path, bundle *b)
{
	if (rsc_folder_path == NULL || b == NULL)
		return AUL_RESOURCE_ERROR_INVALID_PARAMETER;

	return __init(rsc_folder_path, b);
}


SLPAPI int aul_resource_manager_get_path_list(GHashTable **list)
{
	if (is_slice == FALSE)
		return AUL_RESOURCE_ERROR_IO_ERROR;

	if (valid_path_list != NULL)
		*list = valid_path_list;
	else
		return AUL_RESOURCE_ERROR_IO_ERROR;

	return AUL_RESOURCE_ERROR_NONE;
}

SLPAPI int aul_resource_manager_get(aul_resource_e type, const char *id, char **path)
{
	int retval = AUL_RESOURCE_ERROR_NONE;
	char *put_fname = NULL;
	const char *cached_path = NULL;
	GList *list = NULL;
	resource_group_t *resource_group = NULL;
	resource_node_t *resource_node = NULL;

	*path = NULL;

	if (id == NULL) {
		LOGE("INVALID_PARAMETER(0x%08x), resource_data_t",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER);
		return AUL_RESOURCE_ERROR_INVALID_PARAMETER;
	}

	if (type < AUL_RESOURCE_TYPE_MIN || type > AUL_RESOURCE_TYPE_MAX) {
		LOGE("INVALID_PARAMETER(0x%08x), type(%d)",
				AUL_RESOURCE_ERROR_INVALID_PARAMETER, type);
		return AUL_RESOURCE_ERROR_INVALID_PARAMETER;
	}

	if (is_slice == FALSE) {
		if (resource_handle == NULL) {
			retval = aul_resource_manager_init();
			if (retval != AUL_RESOURCE_ERROR_NONE)
				return retval;
		}

		/* To get fname from cache */
		cached_path = __get_cache(type, id);
		if (cached_path != NULL) {
			*path = strdup(cached_path);
			return AUL_RESOURCE_ERROR_NONE;
		}
	}

	if (resource_handle == NULL)
		return AUL_RESOURCE_ERROR_IO_ERROR;

	resource_group = __find_group(resource_handle->data, type);
	if (resource_group == NULL) {
		LOGE("IO_ERROR(0x%08x), failed to get resource_group",
				AUL_RESOURCE_ERROR_IO_ERROR);
		retval = AUL_RESOURCE_ERROR_IO_ERROR;
		goto Exception;
	}

	list = __get_valid_nodes(resource_group, id);
	if (list == NULL) {
		retval = AUL_RESOURCE_ERROR_IO_ERROR;
		goto Exception;
	}

	resource_node = __get_best_node(list);
	if (resource_node == NULL) {
		retval = AUL_RESOURCE_ERROR_IO_ERROR;
		goto Exception;
	} else {
		unsigned int total_len = strlen(res_path)
				+ strlen(resource_node->folder) + strlen(id) + 3;
		put_fname = (char *) calloc(1, total_len);
		if (!put_fname) {
			if (list != NULL)
				g_list_free(list);
			return AUL_RESOURCE_ERROR_OUT_OF_MEMORY;
		}
		snprintf(put_fname, total_len, "%s%s/%s", res_path,
				resource_node->folder, id);
		*path = strdup(put_fname);
	}

	__put_cache(type, id, put_fname);


Exception:
	if (list != NULL)
		g_list_free(list);

	if (put_fname == NULL && resource_group != NULL) {
		char path_buf[MAX_PATH] = { 0, };
		char group_path_buf[MAX_PATH] = { 0, };

		snprintf(path_buf, MAX_PATH - 1, "%s%s/%s", res_path,
				resource_group->folder, id);
		snprintf(group_path_buf, MAX_PATH - 1, "%s/%s", resource_group->folder, id);

		list = g_list_first(resource_group->node_list);
		while (list) {
			resource_node = (resource_node_t *) list->data;
			if (strncmp(group_path_buf, resource_node->folder, strlen(resource_node->folder)) == 0) {
				*path = NULL;
				return AUL_RESOURCE_ERROR_IO_ERROR;
			}
			list = g_list_next(list);
		}

		if (access(path_buf, R_OK) == 0) {
			__put_cache(type, id, path_buf);
			*path = strdup(path_buf);
			retval = AUL_RESOURCE_ERROR_NONE;
		}
	}

	if (put_fname != NULL)
		free(put_fname);

	return retval;
}

static void __free_node_folder_list(gpointer data)
{
	resource_node_list_t *node_data = (resource_node_list_t *)data;
	if (node_data == NULL)
		return;

	if (node_data->folder != NULL) {
		free(node_data->folder);
		node_data->folder = NULL;
	}

	if (node_data->type != NULL) {
		free(node_data->type);
		node_data->type = NULL;
	}

	free(node_data);
}

SLPAPI int aul_resource_manager_release(void)
{
	if (resource_handle != NULL) {
		__close(resource_handle);
		resource_handle = NULL;
	}

	if (attr_key != NULL) {
		g_hash_table_destroy(attr_key);
		attr_key = NULL;
	}

	if (cur_language) {
		free(cur_language);
		cur_language = NULL;
	}

	if (is_slice == FALSE)
		vconf_ignore_key_changed(VCONFKEY_LANGSET, __vconf_cb);
	else {
		if (valid_path_list != NULL) {
			g_hash_table_destroy(valid_path_list);
			valid_path_list = NULL;
		}

		if (supported_lang_list != NULL) {
			g_hash_table_destroy(supported_lang_list);
			supported_lang_list = NULL;
		}

		if (id_list != NULL) {
			g_hash_table_destroy(id_list);
			id_list = NULL;
		}

		if (all_node_list != NULL) {
			g_list_free_full(all_node_list, __free_node_folder_list);
			all_node_list = NULL;
		}
	}
	return AUL_RESOURCE_ERROR_NONE;
}
