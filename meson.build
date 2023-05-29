project('native-common', 'd', version: '0.0.1')

srcs = [
  'libcommon/package.d',
  'libcommon/crypto/package.d',
  'libcommon/crypto/rc4.d',
  'libcommon/crypto/tea.d'
]

lib = library('libcommon',
              srcs,
              version: meson.project_version()
)

libtest = executable('libcommon-test',
                      [srcs, 'test.d'],
                      d_unittest: true,
                      d_debug: 3,
)

test('librarytest', libtest)
