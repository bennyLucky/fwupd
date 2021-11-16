/*
 * Copyright (C) 2021 Denis Pynkin <denis.pynkin@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_NORDIC_HID_FIRMWARE (fu_nordic_hid_firmware_get_type())
G_DECLARE_FINAL_TYPE(FuNordicHidFirmware,
		     fu_nordic_hid_firmware,
		     FU,
		     NORDIC_HID_FIRMWARE,
		     FuFirmware)

FuFirmware *
fu_nordic_hid_firmware_new(void);

guint32
fu_nordic_hid_firmware_get_checksum(FuFirmware *firmware);

