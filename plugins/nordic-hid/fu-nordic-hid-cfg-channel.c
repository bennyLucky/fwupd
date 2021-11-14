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

#include "fu-nordic-hid-cfg-channel.h"

#define HID_REPORT_ID		6
#define REPORT_SIZE		30
#define REPORT_DATA_MAX_LEN	25
#define HWID_LEN		8
#define END_OF_TRANSFER_CHAR	0x0a

#define FU_NORDIC_HID_CFG_CHANNEL_RETRIES 5
#define FU_NORDIC_HID_CFG_CHANNEL_RETRY_DELAY 100 /* ms */

typedef enum {
	CONFIG_STATUS_PENDING,
	CONFIG_STATUS_GET_MAX_MOD_ID,
	CONFIG_STATUS_GET_HWID,
	CONFIG_STATUS_GET_BOARD_NAME,
	CONFIG_STATUS_INDEX_PEERS,
	CONFIG_STATUS_GET_PEER,
	CONFIG_STATUS_SET,
	CONFIG_STATUS_FETCH,
	CONFIG_STATUS_SUCCESS,
	CONFIG_STATUS_TIMEOUT,
	CONFIG_STATUS_REJECT,
	CONFIG_STATUS_WRITE_FAIL,
	CONFIG_STATUS_DISCONNECTED,
	CONFIG_STATUS_FAULT = 99,
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
	/* TODO: refactor to GHashTable? */
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
	guint8 flash_area_id;
	guint32 flashed_image_len;
	guint8 ver_major;
	guint8 ver_minor;
	guint16 ver_rev;
	guint32 ver_build_nr;
	/* TODO: refactor to GHashTable? */
	GPtrArray *modules; /* of FuNordicCfgChannelModule */
};

G_DEFINE_TYPE(FuNordicDeviceCfgChannel, fu_nordic_hid_cfg_channel, FU_TYPE_UDEV_DEVICE)

static gboolean
fu_nordic_hid_cfg_channel_send(FuNordicDeviceCfgChannel *self,
				  guint8 *buf,
				  guint8 size,
				  GError **error)
{
#ifdef HAVE_HIDRAW_H
	if (g_getenv("FWUPD_NORDIC_HID_VERBOSE") != NULL)
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
fu_nordic_hid_cfg_channel_receive(FuNordicDeviceCfgChannel *self,
				     guint8 *buf,
				     guint8 size,
				     GError **error)
{
#ifdef HAVE_HIDRAW_H
	if (!fu_udev_device_ioctl(FU_UDEV_DEVICE(self), HIDIOCGFEATURE(size), buf, NULL, error)) {
		return FALSE;
	}
	if (g_getenv("FWUPD_NORDIC_HID_VERBOSE") != NULL)
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
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "<linux/hidraw.h> not available");
	return FALSE;
#endif
}

static gboolean
fu_nordic_hid_cfg_channel_receive_cb(FuDevice *device, gpointer user_data, GError **error)
{
	FuNordicCfgChannelRcvHelper *args = (FuNordicCfgChannelRcvHelper *)user_data;
	FuNordicDeviceCfgChannel *self = FU_NORDIC_HID_CFG_CHANNEL(device);
	FuNordicCfgChannelMsg *recv_msg = NULL;

	if (!fu_nordic_hid_cfg_channel_receive(self, args->buf, args->size, error))
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

/*
 * fu_nordic_hid_cfg_channel_get_event_id:
 * @module_name: module name, NULL for generic operations
 * @option_name: option name, NULL for generic module operations
 *
 * Construct Event ID from module and option names.
 *
 * Returns: %TRUE if module/option pair found
 */
static gboolean
fu_nordic_hid_cfg_channel_get_event_id(FuNordicDeviceCfgChannel *self,
				       const gchar *module_name,
				       const gchar *option_name,
				       guint8 *event_id)
{
	guint id = 0;
	FuNordicCfgChannelModule *mod;

	*event_id = 0;
	/* For generic operations */
	if (module_name == NULL)
		return TRUE;

	for (id = 0; id < self->modules->len; id++) {
		mod = g_ptr_array_index(self->modules, id);
		if (!g_strcmp0(module_name, mod->name))
			break;
	}
	if (id >= self->modules->len || id > 0x0f)
		return FALSE;

	*event_id = id << 4;
	/* For generic module operations */
	if (option_name == NULL)
		return TRUE;

	for (guint i = 0; i < mod->options->len && i <= 0x0f; i++) {
		FuNordicCfgChannelModuleOption *opt = g_ptr_array_index(mod->options, i);
		if (!g_strcmp0(option_name, opt->name)) {
			*event_id = (id << 4) + opt->idx;
			return TRUE;
		}
	}

	/* module have no requested option */
	return FALSE;
}

static gboolean
fu_nordic_hid_cfg_channel_dfu_cmd_send_by_id(FuNordicDeviceCfgChannel *self,
					     guint8 recipient,
					     guint8 event_id,
					     guint8 status,
					     GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) msg = g_new0(FuNordicCfgChannelMsg, 1);

	msg->report_id = HID_REPORT_ID;
	msg->recipient = recipient;
	msg->event_id = event_id;
	msg->status = status;
	msg->data_len = 0;
	if (!fu_nordic_hid_cfg_channel_send(self, (guint8 *)msg, sizeof(*msg), error)) {
		g_prefix_error(error, "Failed to send: ");
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_nordic_hid_cfg_channel_dfu_cmd_send(FuNordicDeviceCfgChannel *self,
				       guint8 recipient,
				       const gchar *module_name,
				       const gchar *option_name,
				       guint8 status,
				       GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) msg = g_new0(FuNordicCfgChannelMsg, 1);
	guint8 event_id = 0;

	if (!fu_nordic_hid_cfg_channel_get_event_id(self, module_name, option_name, &event_id)) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "Requested non-existing module %s with option %s",
			    module_name,
			    option_name);
		return FALSE;
	}

	if (!fu_nordic_hid_cfg_channel_dfu_cmd_send_by_id(self,
							  recipient,
							  event_id,
							  status,
							  error)) {
		g_prefix_error(error, "Failed to send: ");
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_nordic_hid_cfg_channel_dfu_cmd_receive(FuNordicDeviceCfgChannel *self,
					  gboolean check_status,
					  guint8 status,
					  FuNordicCfgChannelMsg *res,
					  GError **error)
{
	FuNordicCfgChannelRcvHelper helper;

	res->report_id = HID_REPORT_ID;
	helper.check_status = check_status;
	helper.status = status;
	helper.buf = (guint8 *)res;
	helper.size = sizeof(*res);
	if (!fu_device_retry(FU_DEVICE(self),
			     fu_nordic_hid_cfg_channel_receive_cb,
			     FU_NORDIC_HID_CFG_CHANNEL_RETRIES,
			     &helper,
			     error)) {
		g_prefix_error(error, "Failed on receive: ");
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_nordic_hid_cfg_channel_get_board_name(FuNordicDeviceCfgChannel *self, GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);

	if (!fu_nordic_hid_cfg_channel_dfu_cmd_send(self,
						    0,
						    NULL,
						    NULL,
						    CONFIG_STATUS_GET_BOARD_NAME,
						    error))
		return FALSE;
	if (!fu_nordic_hid_cfg_channel_dfu_cmd_receive(self,
						       TRUE,
						       CONFIG_STATUS_SUCCESS,
						       res,
						       error))
		return FALSE;

	self->board_name = g_strndup((gchar *)res->data, res->data_len);

	return TRUE;
}

/*
 * NOTE:
 * For devices connected directly to the host,
 * hw_id = HID_UNIQ = logical_id.
 */
static gboolean
fu_nordic_hid_cfg_channel_get_hwid(FuNordicDeviceCfgChannel *self,
				      GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);

	if (!fu_nordic_hid_cfg_channel_dfu_cmd_send(self,
						    0,
						    NULL,
						    NULL,
						    CONFIG_STATUS_GET_HWID,
						    error))
		return FALSE;
	if (!fu_nordic_hid_cfg_channel_dfu_cmd_receive(self,
						       TRUE,
						       CONFIG_STATUS_SUCCESS,
						       res,
						       error))
		return FALSE;

	memcpy(self->hw_id, res->data, HWID_LEN);

	return TRUE;
}

static gboolean
fu_nordic_hid_cfg_channel_load_module_opts(FuNordicDeviceCfgChannel *self,
					      FuNordicCfgChannelModule *mod,
					      GError **error)
{
	guint i = 0; /* initial module idx */

	while (TRUE) {
		FuNordicCfgChannelModuleOption *opt = NULL;
		g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);

		if (!fu_nordic_hid_cfg_channel_dfu_cmd_send_by_id(self,
								  0,
								  mod->idx << 4,
								  CONFIG_STATUS_FETCH,
								  error))
			return FALSE;
		if (!fu_nordic_hid_cfg_channel_dfu_cmd_receive(self,
							       TRUE,
							       CONFIG_STATUS_SUCCESS,
							       res,
							       error))
			return FALSE;

		/* res->data: option name */
		if (res->data[0] == END_OF_TRANSFER_CHAR)
			break;
		opt = g_new0(FuNordicCfgChannelModuleOption, 1);
		opt->name = g_strndup((gchar *)res->data, res->data_len);
		opt->idx = i;
		g_ptr_array_add(mod->options, opt);
		i++;
	}

	return TRUE;
}

static gboolean
fu_nordic_hid_cfg_channel_load_module_info(FuNordicDeviceCfgChannel *self,
					      guint8 module_idx,
					      GError **error)
{
	FuNordicCfgChannelModule *mod = g_new0(FuNordicCfgChannelModule, 1);
	FuNordicCfgChannelModuleOption *opt = NULL;

	mod->idx = module_idx;
	mod->options = g_ptr_array_new();
	if (!fu_nordic_hid_cfg_channel_load_module_opts(self, mod, error))
		return FALSE;
	/* Module description is the 1-st loaded option */
	if (mod->options->len > 0) {
		opt = g_ptr_array_index(mod->options, 0);
		mod->name = g_strdup(opt->name);
		if (!g_ptr_array_remove(mod->options, opt))
			g_set_error_literal(error,
					    FWUPD_ERROR,
					    FWUPD_ERROR_INTERNAL,
					    "Unexpected internal error");
	}

	g_ptr_array_add(self->modules, mod);

	return TRUE;
}

/* TODO: remove */
static void
print_opt_cb(gpointer data, gpointer user_data)
{
	FuNordicCfgChannelModuleOption *opt = data;
	g_debug("  Option %d: %s", opt->idx, opt->name);
}

/* TODO: remove */
static void
print_mod_cb(gpointer data, gpointer user_data)
{
	FuNordicCfgChannelModule *mod = data;

	g_debug("Module %d: '%s' with %u options:", mod->idx, mod->name, mod->options->len);
	g_ptr_array_foreach(mod->options, print_opt_cb, NULL);
}

static gboolean
fu_nordic_hid_cfg_channel_get_modinfo(FuNordicDeviceCfgChannel *self,
					 GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);

	if (!fu_nordic_hid_cfg_channel_dfu_cmd_send(self,
						    0,
						    NULL,
						    NULL,
						    CONFIG_STATUS_GET_MAX_MOD_ID,
						    error))
		return FALSE;
	if (!fu_nordic_hid_cfg_channel_dfu_cmd_receive(self,
						       TRUE,
						       CONFIG_STATUS_SUCCESS,
						       res,
						       error))
		return FALSE;

	/* res->data[0]: maximum module idx */
	self->modules = g_ptr_array_new();
	for (guint i = 0; i <= res->data[0]; i++) {
		if (!fu_nordic_hid_cfg_channel_load_module_info(self, i, error))
			return FALSE;
	}

	/* TODO: remove */
	g_ptr_array_foreach(self->modules, print_mod_cb, NULL);
	return TRUE;
}

static gboolean
fu_nordic_hid_cfg_channel_dfu_fwinfo(FuNordicDeviceCfgChannel *self, GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);

	if (!fu_nordic_hid_cfg_channel_dfu_cmd_send(self,
						    0,
						    "dfu",
						    "fwinfo",
						    CONFIG_STATUS_FETCH,
						    error))
		return FALSE;
	if (!fu_nordic_hid_cfg_channel_dfu_cmd_receive(self,
						       TRUE,
						       CONFIG_STATUS_SUCCESS,
						       res,
						       error))
		return FALSE;

	/* Parsing fwinfo answer */
	self->flash_area_id = res->data[0];
	if (!fu_common_read_uint32_safe(res->data,
					REPORT_SIZE,
					0x01,
					&self->flashed_image_len,
					G_LITTLE_ENDIAN,
					error))
		return FALSE;
	self->ver_major = res->data[4];
	self->ver_minor = res->data[5];
	if (!fu_common_read_uint16_safe(res->data,
					REPORT_SIZE,
					0x07,
					&self->ver_rev,
					G_LITTLE_ENDIAN,
					error))
		return FALSE;
	if (!fu_common_read_uint32_safe(res->data,
					REPORT_SIZE,
					0x09,
					&self->ver_build_nr,
					G_LITTLE_ENDIAN,
					error))
		return FALSE;

	if (g_getenv("FWUPD_NORDIC_HID_VERBOSE") != NULL) {
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "Flash area ID: %u", self->flash_area_id);
		g_log(G_LOG_DOMAIN,
		      G_LOG_LEVEL_DEBUG,
		      "Flashed image size: %u",
		      self->flashed_image_len);
		g_log(G_LOG_DOMAIN,
		      G_LOG_LEVEL_DEBUG,
		      "Image version: %u.%u.%u.%u",
		      self->ver_major,
		      self->ver_minor,
		      self->ver_rev,
		      self->ver_build_nr);
	}

	return TRUE;
}

static gboolean
fu_nordic_hid_cfg_channel_dfu_reboot(FuNordicDeviceCfgChannel *self, GError **error)
{
	g_autoptr(FuNordicCfgChannelMsg) res = g_new0(FuNordicCfgChannelMsg, 1);

	if (!fu_nordic_hid_cfg_channel_dfu_cmd_send(self,
						    0,
						    "dfu",
						    "reboot",
						    CONFIG_STATUS_FETCH,
						    error))
		return FALSE;
	if (!fu_nordic_hid_cfg_channel_dfu_cmd_receive(self,
						       TRUE,
						       CONFIG_STATUS_SUCCESS,
						       res,
						       error))
		return FALSE;

	if (res->data_len != 1 || res->data[0] != 0x01) {
		return FALSE;
	}

	return TRUE;
}

static gboolean
fu_nordic_hid_cfg_channel_probe(FuDevice *device, GError **error)
{
	/* FuUdevDevice->probe */
	if (!FU_DEVICE_CLASS(fu_nordic_hid_cfg_channel_parent_class)->probe(device, error))
		return FALSE;

	return fu_udev_device_set_physical_id(FU_UDEV_DEVICE(device), "hid", error);
}

static gboolean
fu_nordic_hid_cfg_channel_setup(FuDevice *device, GError **error)
{
	FuNordicDeviceCfgChannel *self = FU_NORDIC_HID_CFG_CHANNEL(device);
	g_autofree gchar *version = NULL;

	/* get device info */
	if (!fu_nordic_hid_cfg_channel_get_board_name(self, error))
		return FALSE;
	if (!fu_nordic_hid_cfg_channel_get_hwid(self, error))
		return FALSE;
	if (!fu_nordic_hid_cfg_channel_get_modinfo(self, error))
		return FALSE;
	if (!fu_nordic_hid_cfg_channel_dfu_fwinfo(self, error))
		return FALSE;

	version = g_strdup_printf("%u.%u.%u.%u",
				  self->ver_major,
				  self->ver_minor,
				  self->ver_rev,
				  self->ver_build_nr);
	fu_device_set_version(FU_DEVICE(device), version);

	return TRUE;
}

static void
fu_nordic_hid_cfg_channel_set_progress(FuDevice *self, FuProgress *progress)
{
	fu_progress_set_id(progress, G_STRLOC);
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 1); /* detach */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_WRITE, 97);	/* write */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_RESTART, 1); /* attach */
	fu_progress_add_step(progress, FWUPD_STATUS_DEVICE_BUSY, 1);	/* reload */
}

static void
fu_nordic_hid_cfg_channel_to_string(FuDevice *device, guint idt, GString *str)
{
	FuNordicDeviceCfgChannel *self = FU_NORDIC_HID_CFG_CHANNEL(device);

	fu_common_string_append_kv(str, idt, "BoardName", self->board_name);
}

static gboolean
fu_nordic_hid_cfg_channel_write_firmware(FuDevice *device,
					 FuFirmware *firmware,
					 FuProgress *progress,
					 FwupdInstallFlags flags,
					 GError **error)
{
	FuNordicDeviceCfgChannel *self = FU_NORDIC_HID_CFG_CHANNEL(device);
	g_autoptr(GBytes) blob = NULL;
	g_autoptr(GPtrArray) chunks = NULL;

	blob = fu_firmware_get_bytes(firmware, error);
	if (blob == NULL)
		return FALSE;

	chunks = fu_chunk_array_new_from_bytes(blob, 0, 0, REPORT_SIZE);

	g_warning("RESET");
	return fu_nordic_hid_cfg_channel_dfu_reboot(self, error);
}

static void
fu_nordic_hid_cfg_channel_module_free(FuNordicCfgChannelModule *mod)
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
fu_nordic_hid_cfg_channel_finalize(GObject *object)
{
	FuNordicDeviceCfgChannel *self = FU_NORDIC_HID_CFG_CHANNEL(object);
	g_free(self->board_name);
	if (self->modules != NULL) {
		for (guint i = 0; i < self->modules->len; i++) {
			FuNordicCfgChannelModule *mod = g_ptr_array_index(self->modules, i);
			fu_nordic_hid_cfg_channel_module_free(mod);
		}
		g_ptr_array_unref(self->modules);
	}
	G_OBJECT_CLASS(fu_nordic_hid_cfg_channel_parent_class)->finalize(object);
}

static void
fu_nordic_hid_cfg_channel_class_init(FuNordicDeviceCfgChannelClass *klass)
{
	FuDeviceClass *klass_device = FU_DEVICE_CLASS(klass);
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	klass_device->probe = fu_nordic_hid_cfg_channel_probe;
	klass_device->setup = fu_nordic_hid_cfg_channel_setup;
	klass_device->to_string = fu_nordic_hid_cfg_channel_to_string;
	klass_device->write_firmware = fu_nordic_hid_cfg_channel_write_firmware;
	klass_device->set_progress = fu_nordic_hid_cfg_channel_set_progress;
	object_class->finalize = fu_nordic_hid_cfg_channel_finalize;
}

static void
fu_nordic_hid_cfg_channel_init(FuNordicDeviceCfgChannel *self)
{
	fu_device_set_vendor(FU_DEVICE(self), "Nordic");
	fu_device_add_flag(FU_DEVICE(self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_set_version_format(FU_DEVICE(self), FWUPD_VERSION_FORMAT_QUAD);
	fu_device_add_protocol(FU_DEVICE(self), "com.nordic.nrf.cfgchannel");
	fu_device_retry_set_delay(FU_DEVICE(self), FU_NORDIC_HID_CFG_CHANNEL_RETRY_DELAY);
}
