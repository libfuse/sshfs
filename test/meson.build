test_scripts = [ 'conftest.py', 'pytest.ini', 'test_sshfs.py',
                 'util.py' ]
custom_target('test_scripts', input: test_scripts,
              output: test_scripts, build_by_default: true,
              command: ['cp', '-fPp', 
                        '@INPUT@', meson.current_build_dir() ])

# Provide something helpful when running 'ninja test'
wrong_cmd = executable('wrong_command', 'wrong_command.c',
                       install: false)
test('wrong_cmd', wrong_cmd)
