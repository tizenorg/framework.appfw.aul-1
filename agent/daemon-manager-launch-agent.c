#include <glib.h>
#include <gio/gio.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef WEARABLE_PROFILE
#define DAEMON_MANAGER_NAME "com.samsung.DaemonManager"
#define DAEMON_MANAGER_PATH "/com/samsung/DaemonManager"
#define DAEMON_MANAGER_INTERFACE "com.samsung.DaemonManager"
#else
#define DAEMON_MANAGER_NAME "org.tizen.DaemonManager"
#define DAEMON_MANAGER_PATH "/org/tizen/DaemonManager"
#define DAEMON_MANAGER_INTERFACE "org.tizen.DaemonManager"
#endif

#define METHOD_RELEASED "Start"

#define BUS_TYPE G_BUS_TYPE_SYSTEM

#define LOG_PATH "/tmp/dmlaunch.err"

static void elog(const char *fmt, ...)
{
	FILE *fp;
	va_list ap;

	fp = fopen(LOG_PATH, "w+");
	if (!fp)
		return;

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);

	fclose(fp);
}

int main(int argc, char *argv[])
{
	GError *err;
	GDBusProxy *proxy = NULL;
	GDBusConnection *conn = NULL;
	GVariant *res = NULL;

	if (argc < 2) {
		elog("usage) %s path\n", argv[0]);
		return 1;
	}

	g_type_init();

	/* TODO: use private bus? */
	err = NULL;
	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (!conn) {
		elog("Connection failed: %s\n", err ? err->message : "");
		goto err;
	}

	err = NULL;
	proxy = g_dbus_proxy_new_sync(conn,
			G_DBUS_PROXY_FLAGS_NONE,
			NULL,
			DAEMON_MANAGER_NAME,
			DAEMON_MANAGER_PATH,
			DAEMON_MANAGER_INTERFACE,
			NULL,
			&err);
	if (!proxy) {
		elog("Proxy new: %s\n", err ? err->message : "");
		goto err;
	}

	err = NULL;
	res = g_dbus_proxy_call_sync(proxy,
			METHOD_RELEASED,
			g_variant_new("(s)", argv[1]),
			G_DBUS_CALL_FLAGS_NONE,
			-1,
			NULL,
			&err);
	if (!res) {
		elog("Call error: %s\n", err ? err->message : "");
		goto err;
	}

err:
	if (res)
		g_variant_unref(res);

	if (proxy)
		g_object_unref(proxy);

	if (conn)
		g_object_unref(conn);

	if (err) {
		g_clear_error(&err);
		return 1;
	}

	return 0;
}

