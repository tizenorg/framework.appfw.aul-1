#define _GNU_SOURCE
#include <string.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <pkgmgr-info.h>
#include "aul.h"
#include "aul_svc.h"
#include "delegator_config.h"
#include "delegator_client_gdbus_generated.h"
#include "delegator_client.h"
#include "aul_svc_priv_key.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "DELEGATOR_CLIENT"

int delegator_client_launch(const char *zone, bundle* kb)
{
	GError *error = NULL;
	int ret = 0;
	GDBusConnection *conn;
	OrgTizenAulDelegator *proxy;

	if (zone == NULL)
		return AUL_SVC_RET_EINVAL;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (error) {
		SECURE_LOGE("gdbus connection error (%s)", error->message);
		g_error_free(error);
	}
	if (conn == NULL) {
		SECURE_LOGE(
				"gdbus connection is not set, even gdbus error isn't raised");
		return AUL_SVC_RET_ERROR;
	}

	proxy = org_tizen_aul_delegator_proxy_new_sync(conn,
			G_DBUS_PROXY_FLAGS_NONE, DELEGATOR_INTERFACE,
			DELEGATOR_NODE,
			NULL, &error);
	if (proxy == NULL) {
		SECURE_LOGE("Unable to create proxy[err=%s]\n", error->message);
		g_error_free(error);
		g_object_unref(conn);
		return AUL_SVC_RET_ERROR;
	}

	bundle_raw* br = NULL;
	int len;

	if (kb != NULL) {
		bundle_encode(kb, &br, &len);
	}
	org_tizen_aul_delegator_call_launch_sync(proxy, zone,
			(const gchar *) br, &ret,
			NULL, &error);

	if (br != NULL)
		free(br);
	g_dbus_connection_flush_sync(conn, NULL, NULL);
	g_object_unref(conn);

	return ret;
}

int delegator_client_can_jump(char **zone, bundle *kb)
{
	if (kb != NULL) {
		char *val = NULL;

		bundle_get_str(kb, AUL_SVC_K_OPERATION, &val);
		if (val != NULL && strcmp(AUL_SVC_OPERATION_JUMP, val) == 0) {
			char *op = NULL;
			char *domain = NULL;

			bundle_del(kb, AUL_SVC_K_OPERATION);
			bundle_get_str(kb, AUL_SVC_K_JUMP_ORIGIN_OPERATION, &op);
			bundle_get_str(kb, AUL_SVC_K_JUMP_ZONE_NAME, &domain);

			if (domain != NULL) {
				if (op != NULL) {
					bundle_add_str(kb, AUL_SVC_K_OPERATION, op);
				}

				*zone = strdup(domain);
				bundle_del(kb, AUL_SVC_K_JUMP_ZONE_NAME);
				bundle_del(kb, AUL_SVC_K_JUMP_ORIGIN_OPERATION);
				return AUL_SVC_RET_OK;
			}
		}
	}

	return AUL_SVC_RET_EREJECTED;
}



