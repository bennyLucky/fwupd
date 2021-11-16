/*
 * Copyright (C) 2021 Denis Pynkin <denis.pynkin@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include "fu-nordic-hid-firmware.h"

struct _FuNordicHidFirmware {
	FuIhexFirmwareClass parent_instance;
    guint32 crc32;
};

G_DEFINE_TYPE(FuNordicHidFirmware, fu_nordic_hid_firmware, FU_TYPE_FIRMWARE)

static guint32
fu_nordic_hid_firmware_crc32(GBytes *fw, GError **error)
{
    guint crc32 = 0x01;
    gsize fw_len = 0;
    guint8 const *fw_binary;

    fw_binary = g_bytes_get_data(fw, &fw_len);
    if (fw_binary == NULL)
        return 0;

    /* FIXME: probably skipped "^" step in fu_common_crc32_full()?
     * according https://github.com/madler/zlib/blob/master/crc32.c#L225 */
    crc32 ^= 0xFFFFFFFFUL; 
    crc32 = fu_common_crc32_full(fw_binary, fw_len, crc32, 0xEDB88320);

    return crc32;
}

guint32
fu_nordic_hid_firmware_get_checksum(FuFirmware *firmware)
{
    FuNordicHidFirmware *self = FU_NORDIC_HID_FIRMWARE(firmware);

    return self->crc32;
}

static gboolean
fu_nordic_hid_firmware_parse(FuFirmware *firmware,
			      GBytes *fw,
			      guint64 addr_start,
			      guint64 addr_end,
			      FwupdInstallFlags flags,
			      GError **error)
{
    FuNordicHidFirmware *self = FU_NORDIC_HID_FIRMWARE(firmware);

    self->crc32 = fu_nordic_hid_firmware_crc32(fw, error);
    fu_firmware_set_bytes(firmware, fw);
	return TRUE;
}

static void
fu_nordic_hid_firmware_init(FuNordicHidFirmware *self)
{
}

static void
fu_nordic_hid_firmware_class_init(FuNordicHidFirmwareClass *klass)
{
	FuFirmwareClass *klass_firmware = FU_FIRMWARE_CLASS(klass);
	klass_firmware->parse = fu_nordic_hid_firmware_parse;
}

FuFirmware *
fu_nordic_hid_firmware_new(void)
{
	return FU_FIRMWARE(g_object_new(FU_TYPE_NORDIC_HID_FIRMWARE, NULL));
}

