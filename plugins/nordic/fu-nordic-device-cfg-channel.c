/*
 * Copyright (C) 2021 Ricardo Cañuelo <ricardo.canuelo@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#ifdef HAVE_HIDRAW_H
#include <linux/hidraw.h>
#include <linux/input.h>
#endif
#include <fwupdplugin.h>

#include "fu-nordic-device-cfg-channel.h"

#define HID_REPORT_ID		6
#define REPORT_SIZE		30
#define REPORT_DATA_MAX_LEN	25
#define HWID_LEN		8
#define END_OF_TRANSFER_CHAR	'\n'

#define FU_NORDIC_DEVICE_CFG_CHANNEL_RETRIES 5
#define FU_NORDIC_DEVICE_CFG_CHANNEL_RETRY_DELAY 100 /* ms */

typedef enum {
	CFG_STATUS_PENDING,
	CFG_STATUS_GET_MAX_MOD_ID,
	CFG_STATUS_GET_HWID,
	CFG_STATUS_GET_BOARD_NAME,
	CFG_STATUS_INDEX_PEERS,
	CFG_STATUS_GET_PEER,
	CFG_STATUS_SET,
	CFG_STATUS_FETCH,
	CFG_STATUS_SUCCESS,
	CFG_STATUS_TIMEOUT,
	CFG_STATUS_REJECT,
	CFG_STATUS_WRITE_FAIL,
	CFG_STATUS_DISCONNECTED,
	CFG_STATUS_FAULT = 99,
} FuNordicCfStatus;

typedef struct __attribute__((packed)) {
	guint8 report_id;
	guint8 recipient;
	guint8 event_id;
	guint8 status;
	guint8 data_len;
	guint8 data[REPORT_DATA_MAX_LEN];
} FuNordicCfgChannelMsg;

typedef struct {
	guint8 idx;
	gchar* name;
} FuNordicCfgChannelModuleOption;

typedef struct {
	guint8 idx;
	gchar* name;
	GPtrArray *options; /* of FuNordicCfgChannelModuleOption */
} FuNordicCfgChannelModule;

typedef struct {
	gboolean check_status;
	guint8 status;
	guint8 *buf;
	guint8 size;
} FuNordicCfgChannelRcvHelper;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(FuNordicCfgChannelMsg, g_free);

struct _FuNordicDeviceCfgChannel {
	FuUdevDevice parent_instance;
	gchar *board_name;
	guint8 hw_id[HWID_LEN];
	GPtrArray *modules; /* of FuNordicCfgChannelModule */
};

G_DEFINE_TYPE(FuNordicDeviceCfgChannel, fu_nordic_device_cfg_channel, FU_TYPE_UDEV_DEVICE)

static gboolean
fu_nordic_device_cfg_channel_send(FuNordicDeviceCfgChannel *self,
				  guint8 *buf,
				  guint8 size,
				  GError **error)
{
#ifdef HAVE_HIDRAW_H
	if (g_getenv("FWUPD_NORDIC_VERBOSE") != NULL)
		fu_common_dump_raw(G_LOG_DOMAIN, "Sent", buf, size);
	if (!fu_udev_device_ioctl(FU_UDEV_DEVICE(self),
				  HIDIOCSFEATURE(size),
				  buf,
				  NULL,
				  error)) {
		return FALSE;
	}
	return TRUE;
#else
	g_set_error_literal(error,
			    G_IO_ERROR,
			    G_IO_ERROR_NOT_SUPPORTED,
			    "<linux/hidraw.h> not available");
	return FALSE;
#endif
}

static gboolean
fu_nordic_device_cfg_channel_receive(FuNordicDeviceCfgChannel *self,
				     guint8 *buf,
				     guint8 size,
				     GError **error)
{
#ifdef HAVE_HIDRAW_H
	if (!fu_udev_device_ioctl(FU_UDEV_DEVICE(self), HIDIOCGFEATURE(size), buf, NULL, error)) {
		return FALSE;
	}
	if (g_getenv("FWUPD_NORDIC_VERBOSE") != NULL)
		fu_common_dump_raw(G_LOG_DOMAIN, "Received", buf, size);
	/*
	 * [TODO]: Possibly add the report-id fix for Bluez versions < 5.56:
	 * https://github.com/bluez/bluez/commit/35a2c50437cca4d26ac6537ce3a964bb509c9b62
	 *
	 * See fu_pxi_ble_device_get_feature() in
	 * plugins/pixart-rf/fu-pxi-ble-device.c for an example.
	 */
	return TRUE;
#else
	g_set_error_literal(error,
			    G_IO_ERROR,
			    G_IO_ERROR_NOT_SUPPORTED,
			    "<linux/hidraw.h> not available");
	return FALSE;
#endif
}

static gboolean
fu_nordic_device_cfg_channel_receive_cb(FuDevice *device, gpointer user_data, GError **error)
{
	FuNordicCfgChannelRcvHelper *args = (FuNordicCfgChannelRcvHelper *)user_data;
	FuNordicDeviceCfgChannel *self = FU_NORDIC_DEVICE_CFG_CHANNEL(device);
	FuNordicCfgChannelMsg *recv_msg = NULL;

	if (!fu_nordic_device_cfg_channel_receive(self, args->buf, args->size, error))
		return FALSE;
	recv_msg = (FuNordicCfgChannelMsg *)args->buf;
	if (args->check_status == TRUE && recv_msg->status != args->status) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_READ,
			    "Received status: 0x%02x, expected: 0x%02x",
			    recv_msg->status, args->status);
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_nordic_device_cfg_channel_get_board_name(FuNordicDeviceCfgChannel *self,
					    GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) msg = g_new0(FuNordicCfgChannelMsg, 1);
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);
	FuNordicCfgChannelRcvHelper helper;

	msg->report_id = HID_REPORT_ID;
	msg->recipient = 0;
	msg->event_id = 0;
	msg->status = CFG_STATUS_GET_BOARD_NAME;
	msg->data_len = 0;
	if (!fu_nordic_device_cfg_channel_send(self, (guint8 *)msg, sizeof(*msg), error)) {
		g_prefix_error(error, "Failed to get dev name (send): ");
		return FALSE;
	}
	res->report_id = HID_REPORT_ID;
	helper.check_status = TRUE;
	helper.status = CFG_STATUS_SUCCESS;
	helper.buf = (guint8 *)res;
	helper.size = sizeof(*res);
	if (!fu_device_retry(FU_DEVICE(self),
			     fu_nordic_device_cfg_channel_receive_cb,
			     FU_NORDIC_DEVICE_CFG_CHANNEL_RETRIES,
			     &helper,
			     error)) {
		g_prefix_error(error, "Failed to get dev name (receive): ");
		return FALSE;
	}
	self->board_name = g_strndup((gchar *)res->data, res->data_len);

	return TRUE;
}

/*
 * NOTE:
 * For devices connected directly to the host,
 * hw_id = HID_UNIQ = logical_id.
 */
static gboolean
fu_nordic_device_cfg_channel_get_hwid(FuNordicDeviceCfgChannel *self,
				      GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) msg = g_new0(FuNordicCfgChannelMsg, 1);
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);
	FuNordicCfgChannelRcvHelper helper;

	msg->report_id = HID_REPORT_ID;
	msg->recipient = 0;
	msg->event_id = 0;
	msg->status = CFG_STATUS_GET_HWID;
	msg->data_len = 0;
	if (!fu_nordic_device_cfg_channel_send(self, (guint8 *)msg, sizeof(*msg), error)) {
		g_prefix_error(error, "Failed to get hwid (send): ");
		return FALSE;
	}
	res->report_id = HID_REPORT_ID;
	helper.check_status = TRUE;
	helper.status = CFG_STATUS_SUCCESS;
	helper.buf = (guint8 *)res;
	helper.size = sizeof(*res);
	if (!fu_device_retry(FU_DEVICE(self),
			     fu_nordic_device_cfg_channel_receive_cb,
			     FU_NORDIC_DEVICE_CFG_CHANNEL_RETRIES,
			     &helper,
			     error)) {
		g_prefix_error(error, "Failed to get dev hwid (receive): ");
		return FALSE;
	}
	memcpy(self->hw_id, res->data, HWID_LEN);

	return TRUE;
}

static gboolean
fu_nordic_device_cfg_channel_load_module_opts(FuNordicDeviceCfgChannel *self,
					      FuNordicCfgChannelModule *mod,
					      GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) msg = g_new0(FuNordicCfgChannelMsg, 1);
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);
	FuNordicCfgChannelRcvHelper helper;
	guint i = 1; /* initial module idx */

	while (TRUE) {
		g_autoptr(FuNordicCfgChannelMsg) msg_aux = g_new0(FuNordicCfgChannelMsg, 1);
		g_autoptr(FuNordicCfgChannelMsg) res_aux = g_new0(FuNordicCfgChannelMsg, 1);
		FuNordicCfgChannelModuleOption *opt = NULL;
		FuNordicCfgChannelRcvHelper helper_aux;

		msg_aux->report_id = HID_REPORT_ID;
		msg_aux->recipient = 0;
		msg_aux->event_id = mod->idx << 4;
		msg_aux->status = CFG_STATUS_FETCH;
		msg_aux->data_len = 0;
		if (!fu_nordic_device_cfg_channel_send(self, (guint8 *)msg_aux, sizeof(*msg_aux), error)) {
			g_prefix_error(error, "Failed to get module info for %s (send): ", mod->name);
			return FALSE;
		}
		res_aux->report_id = HID_REPORT_ID;
		helper_aux.check_status = TRUE;
		helper_aux.status = CFG_STATUS_SUCCESS;
		helper_aux.buf = (guint8 *)res;
		helper_aux.size = sizeof(*res);
		if (!fu_device_retry(FU_DEVICE(self),
				     fu_nordic_device_cfg_channel_receive_cb,
				     FU_NORDIC_DEVICE_CFG_CHANNEL_RETRIES,
				     &helper_aux,
				     error)) {
			g_prefix_error(error, "Failed to get module info for %s (receive): ", mod->name);
			return FALSE;
		}
		/* res_aux->data: option name */
		if (res_aux->data[0] == END_OF_TRANSFER_CHAR)
			break;
		opt = g_new0(FuNordicCfgChannelModuleOption, 1);
		opt->name = g_strndup((gchar *)res_aux->data, res_aux->data_len);
		opt->idx = i;
		g_ptr_array_add(mod->options, opt);
		i++;
	}

	msg->report_id = HID_REPORT_ID;
	msg->recipient = 0;
	msg->event_id = mod->idx << 4;
	msg->status = CFG_STATUS_FETCH;
	msg->data_len = 0;
	if (!fu_nordic_device_cfg_channel_send(self, (guint8 *)msg, sizeof(*msg), error)) {
		g_prefix_error(error, "Failed to get module info for %s (send): ", mod->name);
		return FALSE;
	}
	res->report_id = HID_REPORT_ID;
	helper.check_status = TRUE;
	helper.status = CFG_STATUS_SUCCESS;
	helper.buf = (guint8 *)res;
	helper.size = sizeof(*res);
	if (!fu_device_retry(FU_DEVICE(self),
			     fu_nordic_device_cfg_channel_receive_cb,
			     FU_NORDIC_DEVICE_CFG_CHANNEL_RETRIES,
			     &helper,
			     error)) {
		g_prefix_error(error, "Failed to get dev name (receive): ");
		return FALSE;
	}
	if (g_strcmp0((gchar *)res->data, mod->name) != 0) {
		g_set_error_literal(error,
				    FWUPD_ERROR,
				    FWUPD_ERROR_READ,
				    "Unexpected reply");
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_nordic_device_cfg_channel_load_module_info(FuNordicDeviceCfgChannel *self,
					      guint8 module_idx,
					      GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) msg = g_new0(FuNordicCfgChannelMsg, 1);
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);
	FuNordicCfgChannelModule *mod = g_new0(FuNordicCfgChannelModule, 1);
	FuNordicCfgChannelRcvHelper helper;

	msg->report_id = HID_REPORT_ID;
	msg->recipient = 0;
	msg->event_id = module_idx << 4;
	msg->status = CFG_STATUS_FETCH;
	msg->data_len = 0;
	if (!fu_nordic_device_cfg_channel_send(self, (guint8 *)msg, sizeof(*msg), error)) {
		g_prefix_error(error, "Failed to get module name (send): ");
		return FALSE;
	}
	res->report_id = HID_REPORT_ID;
	helper.check_status = TRUE;
	helper.status = CFG_STATUS_SUCCESS;
	helper.buf = (guint8 *)res;
	helper.size = sizeof(*res);
	if (!fu_device_retry(FU_DEVICE(self),
			     fu_nordic_device_cfg_channel_receive_cb,
			     FU_NORDIC_DEVICE_CFG_CHANNEL_RETRIES,
			     &helper,
			     error)) {
		g_prefix_error(error, "Failed to get module name (receive): ");
		return FALSE;
	}
	/* res->data: module name */
	mod->name = g_strndup((gchar *)res->data, res->data_len);
	mod->idx = module_idx;
	mod->options = g_ptr_array_new();
	if (!fu_nordic_device_cfg_channel_load_module_opts(self, mod, error))
		return FALSE;
	g_ptr_array_add(self->modules, mod);

	return TRUE;
}

static gboolean
fu_nordic_device_cfg_channel_get_modinfo(FuNordicDeviceCfgChannel *self,
					 GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) msg = g_new0(FuNordicCfgChannelMsg, 1);
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);
	FuNordicCfgChannelRcvHelper helper;

	msg->report_id = HID_REPORT_ID;
	msg->recipient = 0;
	msg->event_id = 0;
	msg->status = CFG_STATUS_GET_MAX_MOD_ID;
	msg->data_len = 0;
	if (!fu_nordic_device_cfg_channel_send(self, (guint8 *)msg, sizeof(*msg), error)) {
		g_prefix_error(error, "Failed to get number of modules (send): ");
		return FALSE;
	}
	res->report_id = HID_REPORT_ID;
	helper.check_status = TRUE;
	helper.status = CFG_STATUS_SUCCESS;
	helper.buf = (guint8 *)res;
	helper.size = sizeof(*res);
	if (!fu_device_retry(FU_DEVICE(self),
			     fu_nordic_device_cfg_channel_receive_cb,
			     FU_NORDIC_DEVICE_CFG_CHANNEL_RETRIES,
			     &helper,
			     error)) {
		g_prefix_error(error, "Failed to get number of modules (receive): ");
		return FALSE;
	}
	/* res->data[0]: maximum module idx */
	self->modules = g_ptr_array_sized_new(res->data[0] + 1);
	for (guint i = 0; i < res->data[0]; i++) {
		if (!fu_nordic_device_cfg_channel_load_module_info(self, i, error))
			return FALSE;
	}

	return TRUE;
}

static gboolean
fu_nordic_device_cfg_channel_probe(FuDevice *device, GError **error)
{
	/* FuUdevDevice->probe */
	if (!FU_DEVICE_CLASS(fu_nordic_device_cfg_channel_parent_class)->probe(device, error))
		return FALSE;

	return fu_udev_device_set_physical_id(FU_UDEV_DEVICE(device), "hid", error);
}

static gboolean
fu_nordic_device_cfg_channel_setup(FuDevice *device, GError **error)
{
	FuNordicDeviceCfgChannel *self = FU_NORDIC_DEVICE_CFG_CHANNEL(device);

	/* get device info */
	if (!fu_nordic_device_cfg_channel_get_board_name(self, error))
		return FALSE;
	if (!fu_nordic_device_cfg_channel_get_hwid(self, error))
		return FALSE;
	if (!fu_nordic_device_cfg_channel_get_modinfo(self, error))
		return FALSE;

	return TRUE;
}

static void
fu_nordic_device_cfg_channel_module_free(FuNordicCfgChannelModule *mod)
{
	if (mod->options != NULL) {
		for (guint i = 0; i < mod->options->len; i++) {
			FuNordicCfgChannelModuleOption *opt = g_ptr_array_index(mod->options, i);
			g_free(opt->name);
		}
		g_ptr_array_unref(mod->options);
	}
	g_free(mod->name);
}

static void
fu_nordic_device_cfg_channel_finalize(GObject *object)
{
	FuNordicDeviceCfgChannel *self = FU_NORDIC_DEVICE_CFG_CHANNEL(object);
	g_free(self->board_name);
	if (self->modules != NULL) {
		for (guint i = 0; i < self->modules->len; i++) {
			FuNordicCfgChannelModule *mod = g_ptr_array_index(self->modules, i);
			fu_nordic_device_cfg_channel_module_free(mod);
		}
		g_ptr_array_unref(self->modules);
	}
	G_OBJECT_CLASS(fu_nordic_device_cfg_channel_parent_class)->finalize(object);
}

static void
fu_nordic_device_cfg_channel_class_init(FuNordicDeviceCfgChannelClass *klass)
{
	FuDeviceClass *klass_device = FU_DEVICE_CLASS(klass);
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	klass_device->probe = fu_nordic_device_cfg_channel_probe;
	klass_device->setup = fu_nordic_device_cfg_channel_setup;
	object_class->finalize = fu_nordic_device_cfg_channel_finalize;
}

static void
fu_nordic_device_cfg_channel_init(FuNordicDeviceCfgChannel *self)
{
	fu_device_set_vendor(FU_DEVICE(self), "Nordic");
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_PLAIN);
	fu_device_add_protocol(FU_DEVICE(self), "com.nordic.nrfdesktop");
	fu_device_retry_set_delay(FU_DEVICE(self), FU_NORDIC_DEVICE_CFG_CHANNEL_RETRY_DELAY);
}
