/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _APP_LAUNCHPAD_TYPES_H_
#define _APP_LAUNCHPAD_TYPES_H_

enum launchpad_type_e {
	NO_LAUNCHPAD_PID = -1,
	AUL_UTIL_PID = -2,
	WEB_LAUNCHPAD_PID = -3,
#ifdef _APPFW_FEATURE_DEBUG_LAUNCHPAD
	DEBUG_LAUNCHPAD_PID = -4,
#endif
#ifdef _APPFW_FEATURE_PROCESS_POOL
	PROCESS_POOL_LAUNCHPAD_PID = -5,
#endif
};

#endif

