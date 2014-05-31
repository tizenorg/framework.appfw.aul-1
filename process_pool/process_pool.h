/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __PROCESS_POOL_H_
#define __PROCESS_POOL_H_

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

#include <app_sock.h>

int  __create_candidate_process(void);
int  __connect_candidate_process(void);
int  __accept_candidate_process(int server_fd, int* out_client_fd, int* out_client_pid);
void __refuse_candidate_process(int server_fd);
int  __send_pkt_raw_data(int client_fd, app_pkt_t* pkt);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__PROCESS_POOL_H_
