project(
        'n-acd',
        'c',
        version: '1',
        license: 'Apache',
        default_options: [
                'c_std=c11',
        ],
)

add_project_arguments('-D_GNU_SOURCE', language: 'c')
mod_pkgconfig = import('pkgconfig')

sub_clist = subproject('c-list')
sub_crbtree = subproject('c-rbtree')
sub_csiphash = subproject('c-siphash')
sub_csundry = subproject('c-sundry')

dep_clist = sub_clist.get_variable('libclist_dep')
dep_crbtree = sub_crbtree.get_variable('libcrbtree_dep')
dep_csiphash = sub_csiphash.get_variable('libcsiphash_dep')
dep_csundry = sub_csundry.get_variable('libcsundry_dep')

subdir('src')
