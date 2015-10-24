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

#ifndef __AUL_AMD_KEY_H_
#define __AUL_AMD_KEY_H_

#include <Ecore_X.h>

#define X_KEY_PLAYCD "XF86AudioPlay"
#define X_KEY_STOPCD "XF86AudioStop"
#define X_KEY_PAUSECD "XF86AudioPause"
#define X_KEY_NEXTSONG "XF86AudioNext"
#define X_KEY_PREVIOUSSONG "XF86AudioPrev"
#define X_KEY_REWIND "XF86AudioRewind"
#define X_KEY_FASTFORWARD "XF86AudioForward"
#define X_KEY_PLAYPAUSE "XF86AudioPlayPause"
#define X_KEY_BACK "XF86Stop"

int _key_init(void);
int _register_key_event(int pid);
int _unregister_key_event(int pid);
Ecore_X_Window _input_window_get(void);
int _key_grab(const char* key, int grab_mode);
int _key_ungrab(const char* key);

#endif

