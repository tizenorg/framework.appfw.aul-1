/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __AUL_RESOURCE_MANAGER_H__
#define __AUL_RESOURCE_MANAGER_H__

#include <tizen.h>
#include <bundle.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumeration for Resource Types
 * @since_tizen 2.4
 */
typedef enum {
	AUL_RESOURCE_TYPE_IMAGE = 0, /**<Image*/
	AUL_RESOURCE_TYPE_LAYOUT, /**<Edje*/
	AUL_RESOURCE_TYPE_SOUND, /**<Sound*/
	AUL_RESOURCE_TYPE_BIN, /**<Bin*/
	AUL_RESOURCE_TYPE_MIN = AUL_RESOURCE_TYPE_IMAGE,
	AUL_RESOURCE_TYPE_MAX = AUL_RESOURCE_TYPE_BIN,
/*add values between AUL_RESOURCE_TYPE_MIN and AUL_RESOURCE_TYPE_MAX*/
} aul_resource_e;

/**
 * @brief Enumeration for Aul Resource Manager Error.
 * @since_tizen 2.4
 */
typedef enum {
	AUL_RESOURCE_ERROR_NONE = TIZEN_ERROR_NONE, /**< Successful */
	AUL_RESOURCE_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER, /**< Invalid parameter */
	AUL_RESOURCE_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY, /**< Out of memory */
	AUL_RESOURCE_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR, /**< I/O error */
} aul_resource_error_e;

/**
 * @brief Creates resource manager and get from db.
 *
 * @since_tizen 2.4
 * @remarks If resource manager is already exist,
 *			It will just return APP_RESOURCE_ERROR_NONE
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #AUL_RESOURCE_ERROR_NONE Successful
 * @retval #AUL_RESOURCE_ERROR_IO_ERROR IO Internal I/O Error
 * @retval #AUL_RESOURCE_ERROR_OUT_OF_MEMORY Out of memeory
 * @see	aul_resource_manager_release()
 */
int aul_resource_manager_init(void);

/**
 * @brief Creates resource manager and make valid filelist from given attributes.
 *
 * @since_tizen 2.4
 * @remarks If resource manager is already exist,
 *			It will just return APP_RESOURCE_ERROR_NONE
 *			This function should called from resource slice tool only.
 * @param[in] rsc_folder_path path of resource.
 * @param[in] b bundle which contain attributes about target device.
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #AUL_RESOURCE_ERROR_NONE Successful
 * @retval #AUL_RESOURCE_ERROR_IO_ERROR IO Internal I/O Error
 * @retval #AUL_RESOURCE_ERROR_OUT_OF_MEMORY Out of memeory
 * @see	aul_resource_manager_release()
 */
int aul_resource_manager_init_slice(const char *rsc_folder_path, bundle *b);

/**
 * @brief Convert resource ID to path name
 *
 * @since_tizen 2.4
 * @remarks If resource manager is not created yet,
 *			aul_resource_manager_init() will be invoked automatically.
 *			Caller should free the returned pointer.
 * @param[in] type Resource type @see aul_resource_e
 * @param[in] id Resource ID
 * @param[out] path The name of requested resource on success, otherwise NULL
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #AUL_RESOURCE_ERROR_NONE Successful
 * @retval #AUL_RESOURCE_ERROR_INVALID_PARAMETER Invalid Parameter
 * @retval #AUL_RESOURCE_ERROR_IO_ERROR Internal I/O Error
 * @see	aul_resource_manager_init()
 */
int aul_resource_manager_get(aul_resource_e type, const char *id, char **path);

/**
 * @brief Destroys resource manager.
 *
 * @since_tizen 2.4
 * @remarks Please make sure that the instance of resource manager should be released when the application is closing only.
 * 			It is highly recommended way to improve run-time performance.
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #AUL_RESOURCE_ERROR_NONE Successful
 * @see	aul_resource_manager_init()
 */
int aul_resource_manager_release(void);

/**
 * @brief Get valid file path list.
 *
 * @since_tizen 2.4
 * @remarks Please make sure that the instance of resource manager should be released when the application is closing only.
 * 			It is highly recommended way to improve run-time performance.
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #AUL_RESOURCE_ERROR_NONE Successful
 * @see	aul_resource_manager_init()
 */
int aul_resource_manager_get_path_list(GHashTable **list);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __AUL_RESOURCE_MANAGER_H__ */
