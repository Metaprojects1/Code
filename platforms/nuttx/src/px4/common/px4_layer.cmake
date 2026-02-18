# Build the px4 layer for nuttx flat build

add_library(px4_layer
		${KERNEL_SRCS}
		${PX4_SOURCE_DIR}/platforms/common/Serial.cpp
		SerialImpl.cpp
	)

target_link_libraries(px4_layer
	PRIVATE
		${KERNEL_LIBS}
		nuttx_c
		nuttx_arch
		nuttx_mm
	)


if (DEFINED PX4_CRYPTO)
	target_include_directories(px4_layer
		PRIVATE
			${PX4_SOURCE_DIR}/src/drivers/sw_crypto
			${PX4_SOURCE_DIR}/src/drivers/stub_keystore
	)

	if (TARGET crypto_backend)
		target_link_libraries(px4_layer
			PUBLIC
				crypto_backend
		)
	endif()
endif()

target_link_libraries(px4_layer PRIVATE px4_platform)
