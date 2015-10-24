#define _GNU_SOURCE
#include <bundle.h>
#include <string.h>
#include <security-server.h>
#include "aul.h"
#include "aul_svc.h"
#include "aul_zone.h"
#include "delegator_config.h"
#include "delegator_client_gdbus_generated.h"
#include "vasum.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "DELEGATOR_SERVER"

GMainLoop *gMainLoop;
GDBusConnection *context_connection = NULL;
static int result = -1;

static int __get_caller_pid(const char *name)
{
	guint pid = -1;
	GVariant *ret;
	GError *error = NULL;

	ret = g_dbus_connection_call_sync (context_connection,
	                                   "org.freedesktop.DBus",
	                                   "/org/freedesktop/DBus",
	                                   "org.freedesktop.DBus",
	                                   "GetConnectionUnixProcessID",
	                                   g_variant_new ("(s)", name),
	                                   NULL,
	                                   G_DBUS_CALL_FLAGS_NONE,
	                                   -1,
	                                   NULL,
	                                   &error);
	g_variant_get (ret, "(u)", &pid);
	g_variant_unref (ret);

	return pid;
}

static gboolean on_handle_launch(OrgTizenAulDelegator *object,
                                 GDBusMethodInvocation *invocation, const gchar *arg_container,
                                 const gchar *arg_bundle)
{
	SECURE_LOGD("delegator server on_handle_launch(%s)", arg_container);

	vsm_context_h ctx;
	vsm_zone_h dom;

	int pid;
	int ret;
	const char *name = g_dbus_method_invocation_get_sender(invocation);

	pid = __get_caller_pid(name);

	ret = security_server_check_privilege_by_pid(pid, "aul::jump", "x");
	if (ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
		SECURE_LOGE("delegator launch request has been denied by smack");
		org_tizen_aul_delegator_complete_launch(object, invocation,
		        AUL_SVC_RET_EREJECTED);
		return TRUE;
	}

	ctx = vsm_create_context();

	if (ctx) {
		dom = vsm_lookup_zone_by_name(ctx, arg_container);
		if (dom) {
			char *focus = NULL;
			bundle *b = bundle_decode((const bundle_raw *)arg_bundle, strlen(arg_bundle));
			bundle_get_str(b, AUL_SVC_K_FOCUS_ZONE, &focus);
			if (focus == NULL || strcmp(focus, "true") == 0)
				vsm_set_foreground(dom);
			SECURE_LOGD("delegator server domain was changed");

			char *old_zone = NULL;

			aul_set_zone(arg_container, &old_zone);
			result = aul_svc_run_service(b, 0, NULL, NULL);
			bundle_free(b);
			if (old_zone)
				free(old_zone);
			SECURE_LOGD("delegator launch result = %d", result);
			org_tizen_aul_delegator_complete_launch(object, invocation, result);
			vsm_cleanup_context(ctx);
			return TRUE;

		}
		org_tizen_aul_delegator_complete_launch(object, invocation,
		        AUL_SVC_RET_EINVAL);
		vsm_cleanup_context(ctx);
	}

	return TRUE;
}

static void on_name_acquired(GDBusConnection *connection, const gchar *name,
                             gpointer user_data)
{
	SECURE_LOGD("delegator server on_name_acquired ++");

	OrgTizenAulDelegator *skeleton;

	skeleton = org_tizen_aul_delegator_skeleton_new();
	g_signal_connect(skeleton, "handle-launch", G_CALLBACK(on_handle_launch),
	                 NULL);
	g_dbus_interface_skeleton_export(G_DBUS_INTERFACE_SKELETON(skeleton),
	                                 connection,
	                                 DELEGATOR_NODE, NULL);
	context_connection = connection;
	SECURE_LOGD("delegator server on_name_acquired -- ");
}

int main(int argc, char *argv[])
{
	gMainLoop = g_main_loop_new(NULL, FALSE);
	if (!gMainLoop) {
		SECURE_LOGE("delegator server g_main_loop_new failed\n");
		return -1;
	}

	guint id = g_bus_own_name(G_BUS_TYPE_SYSTEM, DELEGATOR_INTERFACE,
	                          G_BUS_NAME_OWNER_FLAGS_NONE, NULL, on_name_acquired, NULL, NULL,
	                          NULL);

	SECURE_LOGD("delegator server Main loop is created.");
	g_main_loop_run(gMainLoop);
	g_bus_unown_name(id);
	g_main_loop_unref(gMainLoop);

	return 0;
}

