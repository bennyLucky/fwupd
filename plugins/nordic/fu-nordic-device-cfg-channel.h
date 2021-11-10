/*
 * Copyright (C) 2021 Ricardo Cañuelo <ricardo.canuelo@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_NORDIC_DEVICE_CFG_CHANNEL (fu_nordic_device_cfg_channel_get_type())
G_DECLARE_FINAL_TYPE(FuNordicDeviceCfgChannel, fu_nordic_device_cfg_channel, FU, NORDIC_DEVICE_CFG_CHANNEL, FuUdevDevice)
