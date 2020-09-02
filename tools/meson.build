

tools_deps = []
if host_machine.system() == 'windows'
	tools_deps += ['../contrib/getopt-shim.c']
endif

builtin_libyaml = get_option('builtin_libyaml')

libyaml = dependency('libyaml',required: false)
if not libyaml.found()
	libyaml = cc.find_library('libyaml', required: false)
	if not libyaml.found()
		builtin_libyaml = true
	endif
endif
builtin_libyaml = true
if builtin_libyaml
	cmake = import('cmake')
	toolchainfile = ''
	if meson.is_cross_build()
		if meson.get_cross_property('mingw_toolchainfile')
			toolchainfile = '-DCMAKE_TOOLCHAIN_FILE='+meson.current_source_dir() + '/common/ci/x86_64-w64-mingw32.cmake'
		endif
	endif
	libyaml_proj = cmake.subproject('libyaml', cmake_options: ['-DENABLE_TESTING=OFF', '-DENABLE_PROGRAMS=OFF', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', toolchainfile])
	libyaml = libyaml_proj.dependency('yaml')
endif

executable('ristsender',
	['ristsender.c', 'yamlparse.c', tools_deps],
	dependencies: [libyaml],
	link_with : [librist],
	include_directories: inc,
	install: true)

executable('ristreceiver',
	['ristreceiver.c','yamlparse.c', tools_deps],
	dependencies: [libyaml],
	link_with : [librist],
	include_directories: inc,
	install: true)

executable('rist2rist',
        ['rist2rist.c', tools_deps],
        link_with : [librist],
		include_directories: inc,
        install: true)
