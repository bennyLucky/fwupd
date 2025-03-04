if get_option('plugin_tpm')
if not get_option('gudev')
  error('gudev is required for tpm')
endif
cargs = ['-DG_LOG_DOMAIN="FuPluginTpm"']

install_data([
  'tpm.quirk',
  ],
  install_dir: join_paths(datadir, 'fwupd', 'quirks.d')
)

plugin_tpm = shared_module('fu_plugin_tpm',
  fu_hash,
  sources : [
    'fu-plugin-tpm.c',
    'fu-tpm-device.c',
    'fu-tpm-v1-device.c',
    'fu-tpm-v2-device.c',
    'fu-tpm-eventlog-common.c',
    'fu-tpm-eventlog-parser.c',
  ],
  include_directories : [
    root_incdir,
    fwupd_incdir,
    fwupdplugin_incdir,
  ],
  install : true,
  install_dir: plugin_dir,
  link_with : [
    fwupdplugin,
    fwupd,
  ],
  c_args : cargs,
  dependencies : [
    plugin_deps,
    tpm2tss,
  ],
)

if get_option('tests')
  env = environment()
  env.set('G_TEST_SRCDIR', meson.current_source_dir())
  env.set('G_TEST_BUILDDIR', meson.current_build_dir())
  env.set('FWUPD_LOCALSTATEDIR', '/tmp/fwupd-self-test/var')
  e = executable(
    'tpm-self-test',
    fu_hash,
    sources : [
      'fu-self-test.c',
      'fu-tpm-device.c',
      'fu-tpm-v1-device.c',
      'fu-tpm-v2-device.c',
      'fu-tpm-eventlog-common.c',
      'fu-tpm-eventlog-parser.c',
    ],
    include_directories : [
      root_incdir,
      fwupd_incdir,
      fwupdplugin_incdir,
    ],
    dependencies : [
      plugin_deps,
      tpm2tss,
    ],
    link_with : [
      fwupd,
      fwupdplugin,
    ],
    c_args : cargs
  )
  test('tpm-self-test', e, env: env)
endif

executable(
  'fwupdtpmevlog',
  fu_hash,
  sources : [
    'fu-tpm-eventlog.c',
    'fu-tpm-eventlog-common.c',
    'fu-tpm-eventlog-parser.c',
  ],
  include_directories : [
    root_incdir,
    fwupd_incdir,
    fwupdplugin_incdir,
  ],
  dependencies : [
      plugin_deps,
      tpm2tss,
  ],
  link_with : [
    fwupd,
    fwupdplugin,
  ],
)

endif
