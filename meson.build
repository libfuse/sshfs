project('sshfs', 'c', version: '2.10.0',
        meson_version: '>= 0.38',
        default_options: [ 'buildtype=plain' ])

add_global_arguments('-D_REENTRANT', '-DHAVE_CONFIG_H', '-O2', '-g',
                     '-Wall', '-Wextra', '-Wno-sign-compare',
                     '-Wmissing-declarations', '-Wwrite-strings',
                     language: 'c')

# Some (stupid) GCC versions warn about unused return values even when they are
# casted to void. This makes -Wunused-result pretty useless, since there is no
# way to suppress the warning when we really *want* to ignore the value.
cc = meson.get_compiler('c')
code = '''
__attribute__((warn_unused_result)) int get_4() {
    return 4;
}
int main(void) {
    (void) get_4();
    return 0;
}'''
if not cc.compiles(code, args: [ '-O0', '-Werror=unused-result' ])
     message('Compiler warns about unused result even when casting to void')
     add_global_arguments('-Wno-unused-result', language: 'c')
endif


cfg = configuration_data()

cfg.set_quoted('PACKAGE_VERSION', meson.project_version())

include_dirs = [ include_directories('.') ]
sshfs_sources = ['sshfs.c', 'cache.c']
if target_machine.system() == 'darwin'
  cfg.set_quoted('IDMAP_DEFAULT', 'user')
  sshfs_sources += [ 'compat/fuse_opt.c', 'compat/darwin_compat.c' ]
  include_dirs += [ include_directories('compat') ]
else
  cfg.set_quoted('IDMAP_DEFAULT', 'none')
endif

configure_file(input: 'sshfs.1.in',
               output: 'sshfs.1',
               configuration : cfg)
configure_file(output: 'config.h',
               configuration : cfg)

sshfs_deps = [ dependency('fuse', version: '>= 2.3'),
               dependency('glib-2.0'),
               dependency('gthread-2.0') ]

executable('sshfs', sshfs_sources,
           include_directories: include_dirs,
           dependencies: sshfs_deps,
           c_args: ['-DFUSE_USE_VERSION=26'],
           install: true,
           install_dir: get_option('bindir'))

# This is a little ugly. Is there a better way to tell Meson that the
# manpage is in the build directory?
install_man(join_paths(meson.current_build_dir(), 'sshfs.1'))

subdir('test')

