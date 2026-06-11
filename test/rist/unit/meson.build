cmocka = dependency('cmocka', required: false, fallback: ['cmocka', 'cmocka_dep'])

if cmocka.found()
	if have_srp
		# stdatomic_dependency mirrors the main librist target so the
		# srp_unit translation units pick up the compat/msvc shim when
		# MSVC's <stdatomic.h> requires /experimental:c11atomics.
		srp_unit_deps = [threads, cmocka, crypto_deps, stdatomic_dependency]
		if host_machine.system() == 'windows'
			srp_unit_deps += cc.find_library('bcrypt')  # random.c calls BCryptGenRandom
		endif
		srp_unit = executable('srp_unit', rev_target,
								'srp_examples.c',
								'../../../contrib/pthread-shim.c',
								'../../../src/crypto/random.c',
								include_directories : inc,
								dependencies : srp_unit_deps,
		)

		test('srp_unit_test', srp_unit, suite:['unit'])
	endif
endif

# Regression test for #208: rist_logging_set with a remote (udp://)
# address must succeed before any rist_*_create call. Does not require
# cmocka - links against the public librist API only.
logging_init_order = executable('logging_init_order',
                                'logging_init_order.c',
                                include_directories : inc,
                                link_with : librist)
test('logging_init_order', logging_init_order, suite:['unit'])

# Advanced Profile (TR-06-3) header parse/build round-trip tests.
# Compiles adv.c directly to access RIST_PRIV (hidden-visibility) symbols.
adv_test_deps = [lz4_lib]
if host_machine.system() == 'windows'
	adv_test_deps += cc.find_library('ws2_32')
endif
test_adv_roundtrip = executable('test_adv_roundtrip',
                                'test_adv_roundtrip.c',
                                '../../../src/adv.c',
                                include_directories : inc,
                                dependencies : adv_test_deps)
test('adv_roundtrip', test_adv_roundtrip, suite:['unit'])

# URL ?profile= parsing exercised through the public rist_parse_address2 API.
test_url_profile_parse = executable('test_url_profile_parse',
                                    'test_url_profile_parse.c',
                                    include_directories : inc,
                                    link_with : librist)
test('url_profile_parse', test_url_profile_parse, suite:['unit'])

# ?profile= URL override semantics inside rist_peer_create.
test_url_profile_override = executable('test_url_profile_override',
                                       'test_url_profile_override.c',
                                       include_directories : inc,
                                       link_with : librist)
test('url_profile_override', test_url_profile_override, suite:['unit'])

# ?srp-compat= URL parsing exercised through the public rist_parse_address2 API.
test_url_srp_compat_parse = executable('test_url_srp_compat_parse',
                                       'test_url_srp_compat_parse.c',
                                       include_directories : inc,
                                       link_with : librist)
test('url_srp_compat_parse', test_url_srp_compat_parse, suite:['unit'])

# Versioned peer-config defaults gate fields by RIST_PEER_CONFIG_VERSION.
test_peer_config_versioned_defaults = executable('test_peer_config_versioned_defaults',
                                                 'test_peer_config_versioned_defaults.c',
                                                 include_directories : inc,
                                                 link_with : librist)
test('peer_config_versioned_defaults', test_peer_config_versioned_defaults, suite:['unit'])

# ?recovery-priority= URL parsing exercised through the public API.
test_url_recovery_priority_parse = executable('test_url_recovery_priority_parse',
                                              'test_url_recovery_priority_parse.c',
                                              include_directories : inc,
                                              link_with : librist)
test('url_recovery_priority_parse', test_url_recovery_priority_parse, suite:['unit'])

# NACK routing peer-selection predicate (header-only, no link needed).
test_nack_peer_select = executable('test_nack_peer_select',
                                   'test_nack_peer_select.c',
                                   include_directories : inc)
test('nack_peer_select', test_nack_peer_select, suite:['unit'])
