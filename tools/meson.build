

tools_deps = []
if host_machine.system() == 'windows'
	tools_deps += ['../contrib/getopt-shim.c']
endif

libyaml = cc.find_library('libyaml')

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
