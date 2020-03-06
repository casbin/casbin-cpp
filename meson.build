project('libcasbin', ['cpp', 'c'],
  version : '0.1.0',
  meson_version: '>= 0.50.0',
  default_options : ['warning_level=3'])


config_h = configuration_data()
config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
configure_file(
  output: 'config.h',
  configuration: config_h,
)
add_project_arguments([
  '-I' + meson.build_root(),
], language: ['cpp', 'c'])

include_dirs = include_directories('include', 'lib', '.')

subdir('include')
subdir('lib')

run_target(
  'format',
  command: ['scripts/format.sh']
)

run_target(
  'release',
  command: ['scripts/release.sh', meson.project_name(), meson.project_version()]
)
