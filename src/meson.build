libnacd_private = static_library('nacd-private',
                                 ['n-acd.c'],
                                 c_args: [
                                        '-fvisibility=hidden',
                                        '-fno-common'
                                 ],
                                 pic: true)
install_headers('n-acd.h')
libnacd_symfile = join_paths(meson.current_source_dir(), 'libnacd.sym')
libnacd_shared = shared_library('nacd',
                                objects: libnacd_private.extract_all_objects(),
                                install: true,
                                soversion: 0,
                                link_depends: libnacd_symfile,
                                link_args: [
                                        '-Wl,--no-undefined',
                                        '-Wl,--version-script=@0@'.format(libnacd_symfile)
                                ])
mod_pkgconfig.generate(libraries: libnacd_shared,
                       version: meson.project_version(),
                       name: 'libnacd',
                       filebase: 'libnacd',
                       description: 'IPv4 Address Conflict Detection')
