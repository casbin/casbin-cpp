libcasbin_sources = [
  'casbin.cc',
]

deps = []

libcasbin = library('casbin', libcasbin_sources, version: meson.project_version(),
                  include_directories: include_dirs,
                  dependencies: deps, install: true,
                  )

pkg = import('pkgconfig')
pkg.generate(libraries: [ libcasbin ],
             version: meson.project_version(),
             name: 'casbin',
             description: 'Casbin Authorization Library',
             subdirs: 'casbin')

libcasbin_dep = declare_dependency(include_directories: include_dirs,
                                 link_with: libcasbin, dependencies: deps)