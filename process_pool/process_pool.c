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

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <errno.h>
#include <stdio.h>
#include <systemd/sd-daemon.h>

#include "process_pool.h"
#include "simple_util.h"

#define TMP_PATH "/tmp"
#define PROCESS_POOL_SERVER "core_process_pool_server"
#define MAX_PENDING_CONNECTIONS 10
#define CONNECT_RETRY_TIME 100 * 1000
#define CONNECT_RETRY_COUNT 3

int __create_candidate_process(void)
{
    struct sockaddr_un addr;
    int fd = -1;
    int listen_fds=0;
    int i;

    _D("[dummy] process pool");

    memset(&addr, 0x00, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%s", TMP_PATH, PROCESS_POOL_SERVER);

    listen_fds = sd_listen_fds(0);
    if (listen_fds < 0)
    {
        _E("invalid systemd environment");
        return -1;
    }
    else if (listen_fds > 0)
    {
        for (i = 0; i < listen_fds; i++)
        {
            fd = SD_LISTEN_FDS_START  + i;
            if (sd_is_socket_unix(fd, SOCK_STREAM, 1, addr.sun_path, 0))
                return fd;
        }
        _E("socket not found: %s", addr.sun_path);
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0)
    {
        _E("socket error");
        goto err_create_process_pool_server;
    }

    unlink(addr.sun_path);

    _D("bind to %s", addr.sun_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        _E("bind error");
        goto err_create_process_pool_server;
    }

    _D("chmod to %s", addr.sun_path);
    if (chmod(addr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
    {
        _E("chmod error");
        goto err_create_process_pool_server;
    }

    _D("listen to %s", addr.sun_path);
    if (listen(fd, MAX_PENDING_CONNECTIONS) == -1)
    {
        _E("listen error");
        goto err_create_process_pool_server;
    }

    _D("__create_process_pool_server done : %d", fd);
    return fd;


err_create_process_pool_server:

    if (fd != -1)
    {
        close(fd);
    }

    return -1;
}


int __connect_candidate_process(void)
{
    struct sockaddr_un addr;
    int fd = -1;
    int retry = CONNECT_RETRY_COUNT;
    int send_ret = -1;
    int client_pid = getpid();

    memset(&addr, 0x00, sizeof(struct sockaddr_un));

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0)
    {
        _E("socket error");

        goto err_connect_process_pool_server;
    }

    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%s", TMP_PATH, PROCESS_POOL_SERVER);


    _D("connect to %s", addr.sun_path);
    while (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        if (errno != ETIMEDOUT || retry <= 0)
        {
            _E("connect error : %d", errno);

            goto err_connect_process_pool_server;
        }

        usleep(CONNECT_RETRY_TIME);
        retry--;
        _D("re-connect to %s (%d)", addr.sun_path, retry);
    }

    send_ret = send(fd, &client_pid, sizeof(client_pid), 0);
    _D("send(%d) : %d", client_pid, send_ret);

    if (send_ret == -1)
    {
        _E("send error");

        goto err_connect_process_pool_server;
    }

    _D("__connect_process_pool_server done : %d", fd);
    return fd;

err_connect_process_pool_server:

    if (fd != -1)
    {
        close(fd);
    }

    return -1;
}


int __accept_candidate_process(int server_fd, int* out_client_fd, int* out_client_pid)
{
    int client_fd = -1, client_pid = 0, recv_ret = 0;

    if (server_fd == -1 || out_client_fd == NULL || out_client_pid == NULL)
    {
        _E("arguments error!");

        goto err__accept_dummy_process;
    }

    client_fd = accept(server_fd, NULL, NULL);

    if (client_fd == -1)
    {
        _E("accept error!");

        goto err__accept_dummy_process;
    }

    recv_ret = recv(client_fd, &client_pid, sizeof(client_pid), MSG_WAITALL);

    if (recv_ret == -1)
    {
        _E("recv error!");

        goto err__accept_dummy_process;
    }

    *out_client_fd = client_fd;
    *out_client_pid = client_pid;

    return *out_client_fd;

err__accept_dummy_process:

    if (client_fd != -1)
    {
        close(client_fd);
    }

    return -1;
}

void __refuse_candidate_process(int server_fd)
{
    int client_fd = -1;

    if (server_fd == -1)
    {
        _E("arguments error!");

        goto err__refuse_dummy_process;
    }

    client_fd = accept(server_fd, NULL, NULL);

    if (client_fd == -1)
    {
        _E("accept error!");

        goto err__refuse_dummy_process;;
    }

    close(client_fd);
    _D("refuse connection!");

err__refuse_dummy_process:
    return;
}


int __send_pkt_raw_data(int client_fd, app_pkt_t* pkt)
{
    int send_ret = 0;
    int pkt_size = 0;

    if (client_fd == -1 || pkt == NULL)
    {
        _E("arguments error!");

        goto err__send_pkt_raw_data;
    }

    pkt_size = sizeof(pkt->cmd) + sizeof(pkt->len) + pkt->len;

    send_ret = send(client_fd, pkt, pkt_size, 0);
    _D("send(%d) : %d / %d", client_fd, send_ret, pkt_size);

    if (send_ret == -1)
    {
        _E("send error!");

        goto err__send_pkt_raw_data;
    }
    else if (send_ret != pkt_size)
    {
        _E("send byte fail!");

        goto err__send_pkt_raw_data;
    }

    return 0;

err__send_pkt_raw_data:

    return -1;
}

