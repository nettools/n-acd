project('n-acd',
        'c',
        version: '1',
        license: 'Apache',
        default_options: [
                'buildtype=release',
                'c_std=c11',
        ])

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

sub_clist = subproject('c-list')

dep_clist = sub_clist.get_variable('libclist_dep')

subdir('src')
