project('native-common', 'd', version: '0.0.1')

lib = library('libcommon',
              'libcommon/package.d',
              version: meson.project_version()
)

libtest = executable('libcommon-test',
                      'test.d',
                      d_unittest: true,
                      d_debug: 3,
)

test('librarytest', libtest)
