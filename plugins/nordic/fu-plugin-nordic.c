/*
 * Copyright (C) 2021 Ricardo Cañuelo <ricardo.canuelo@collabora.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>
#include "fu-nordic-device-cfg-channel.h"

gboolean
fu_plugin_startup(FuPlugin *plugin, GError **error)
{
	return TRUE;
}

void
fu_plugin_init(FuPlugin *plugin)
{
	fu_plugin_set_build_hash(plugin, FU_BUILD_HASH);
	fu_plugin_add_udev_subsystem(plugin, "hidraw");
	fu_plugin_add_device_gtype(plugin, FU_TYPE_NORDIC_DEVICE_CFG_CHANNEL);
}
