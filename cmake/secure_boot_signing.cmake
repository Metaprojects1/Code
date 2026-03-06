# CMake rules for automatic firmware signing as part of build process
# This module integrates firmware signing into the standard CMake build workflow

# Store current directory
get_filename_component(SECURE_BOOT_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
get_filename_component(SECURE_BOOT_TOOLS_DIR "${SECURE_BOOT_CMAKE_DIR}/../../../Tools/secure_boot" ABSOLUTE)

# Configuration options
set(FIRMWARE_SIGNING_ENABLED TRUE CACHE BOOL "Enable automatic firmware signing")
set(FIRMWARE_KEY_INDEX 0 CACHE STRING "Signing key index (0-3)")
set(FIRMWARE_SIGNING_KEY_FILE "" CACHE FILEPATH "Path to firmware signing private key (PEM format)")
set(FIRMWARE_SIGNING_TOOL "${SECURE_BOOT_TOOLS_DIR}/firmware_signer.py" CACHE FILEPATH "Path to firmware_signer.py tool")

# =============================================================================
# Function: add_firmware_signing_target
# =============================================================================
# Creates a custom build target that signs a firmware binary
# 
# Usage:
#   add_firmware_signing_target(
#     TARGET firmware_target
#     INPUT path/to/firmware.elf
#     OUTPUT path/to/firmware_signed.bin
#     KEY_FILE /path/to/private_key.pem
#     KEY_INDEX 0
#   )
#
function(add_firmware_signing_target)
    set(options)
    set(oneValueArgs TARGET INPUT OUTPUT KEY_FILE KEY_INDEX)
    set(multiValueArgs)
    
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT FIRMWARE_SIGNING_ENABLED)
        message(STATUS "[Secure Boot] Firmware signing disabled")
        return()
    endif()
    
    # Validate inputs
    if(NOT ARG_TARGET)
        message(FATAL_ERROR "add_firmware_signing_target: TARGET argument required")
    endif()
    
    if(NOT ARG_INPUT)
        message(FATAL_ERROR "add_firmware_signing_target: INPUT argument required")
    endif()
    
    if(NOT ARG_OUTPUT)
        message(FATAL_ERROR "add_firmware_signing_target: OUTPUT argument required")
    endif()
    
    if(NOT ARG_KEY_FILE)
        set(ARG_KEY_FILE "${FIRMWARE_SIGNING_KEY_FILE}")
    endif()
    
    if(NOT ARG_KEY_INDEX)
        set(ARG_KEY_INDEX "${FIRMWARE_KEY_INDEX}")
    endif()
    
    # Validate tool exists
    if(NOT EXISTS "${FIRMWARE_SIGNING_TOOL}")
        message(FATAL_ERROR "Firmware signing tool not found: ${FIRMWARE_SIGNING_TOOL}")
    endif()
    
    # Check for key file in CI/CD environment
    if(DEFINED ENV{FIRMWARE_SIGNING_KEY})
        # In CI/CD: write secret to temporary file
        file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/.fw_signing_key_tmp.pem" "$ENV{FIRMWARE_SIGNING_KEY}")
        set(ARG_KEY_FILE "${CMAKE_CURRENT_BINARY_DIR}/.fw_signing_key_tmp.pem")
        message(STATUS "[Secure Boot] Using signing key from CI/CD environment variable")
    elseif(ARG_KEY_FILE AND EXISTS "${ARG_KEY_FILE}")
        message(STATUS "[Secure Boot] Using signing key: ${ARG_KEY_FILE}")
    else()
        message(FATAL_ERROR "Firmware signing key not found. Set FIRMWARE_SIGNING_KEY_FILE or FIRMWARE_SIGNING_KEY environment variable")
    endif()
    
    # Get Python executable
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    
    # Create signing command
    set(SIGN_COMMAND
        ${Python3_EXECUTABLE} "${FIRMWARE_SIGNING_TOOL}"
        sign
        --firmware "${ARG_INPUT}"
        --private-key "${ARG_KEY_FILE}"
        --output "${ARG_OUTPUT}"
        --key-index ${ARG_KEY_INDEX}
    )
    
    # Create verification command
    set(VERIFY_COMMAND
        ${Python3_EXECUTABLE} "${FIRMWARE_SIGNING_TOOL}"
        verify
        "${ARG_OUTPUT}"
    )
    
    # Add custom command to sign firmware after build
    add_custom_command(
        OUTPUT "${ARG_OUTPUT}"
        COMMAND ${SIGN_COMMAND}
        COMMAND ${VERIFY_COMMAND}
        DEPENDS "${ARG_INPUT}"
        COMMENT "[Secure Boot] Signing firmware: ${ARG_INPUT}"
        VERBATIM
    )
    
    # Add custom target
    add_custom_target(
        ${ARG_TARGET}
        ALL
        DEPENDS "${ARG_OUTPUT}"
    )
    
    message(STATUS "[Secure Boot] Created firmware signing target: ${ARG_TARGET}")
    message(STATUS "               Input:  ${ARG_INPUT}")
    message(STATUS "               Output: ${ARG_OUTPUT}")
    message(STATUS "               Key:    ${ARG_KEY_FILE}")
    
endfunction()

# =============================================================================
# Function: add_firmware_verification_check
# =============================================================================
# Creates a test target that verifies firmware signature
#
function(add_firmware_verification_check)
    set(options)
    set(oneValueArgs FIRMWARE)
    set(multiValueArgs)
    
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT ARG_FIRMWARE)
        message(FATAL_ERROR "add_firmware_verification_check: FIRMWARE argument required")
    endif()
    
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    
    add_test(
        NAME secure_boot_verify_firmware
        COMMAND ${Python3_EXECUTABLE} "${FIRMWARE_SIGNING_TOOL}" verify "${ARG_FIRMWARE}"
    )
    
    set_tests_properties(secure_boot_verify_firmware PROPERTIES
        TIMEOUT 30
    )
    
endfunction()

# =============================================================================
# Function: add_firmware_metadata_check
# =============================================================================
# Validates firmware metadata and checksum
#
function(add_firmware_metadata_check)
    set(options)
    set(oneValueArgs FIRMWARE OUTPUT_VAR)
    set(multiValueArgs)
    
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT ARG_FIRMWARE)
        message(FATAL_ERROR "add_firmware_metadata_check: FIRMWARE argument required")
    endif()
    
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    
    # Run Python script to extract metadata
    set(METADATA_SCRIPT "
import sys
import struct

try:
    with open('${ARG_FIRMWARE}', 'rb') as f:
        f.seek(-128, 2)  # Last 128 bytes
        data = f.read()
    
    magic, version, flags, fw_size, crc32_val = struct.unpack('<IHHII', data[:16])
    
    print(f'Magic: 0x{magic:08X}')
    print(f'Version: {(version >> 8)}.{(version & 0xFF):02d}')
    print(f'Firmware Size: {fw_size} bytes')
    print(f'CRC32: 0x{crc32_val:08X}')
    
    if magic != 0xDEADBEEF:
        print('ERROR: Invalid firmware magic number')
        sys.exit(1)
    
    print('SUCCESS: Firmware metadata valid')
    sys.exit(0)
except Exception as e:
    print(f'ERROR: {e}')
    sys.exit(1)
")
    
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "${METADATA_SCRIPT}"
        RESULT_VARIABLE METADATA_CHECK_RESULT
        OUTPUT_VARIABLE METADATA_CHECK_OUTPUT
    )
    
    if(METADATA_CHECK_RESULT EQUAL 0)
        message(STATUS "[Secure Boot] Firmware metadata check passed:")
        message(STATUS "${METADATA_CHECK_OUTPUT}")
        if(ARG_OUTPUT_VAR)
            set(${ARG_OUTPUT_VAR} "VALID" PARENT_SCOPE)
        endif()
    else()
        message(FATAL_ERROR "[Secure Boot] Firmware metadata check failed:\n${METADATA_CHECK_OUTPUT}")
    endif()
    
endfunction()

# =============================================================================
# Function: setup_firmware_signing_in_project
# =============================================================================
# Convenience function to set up firmware signing for a complete project
#
# Usage:
#   setup_firmware_signing_in_project(
#     PROJECT_NAME myproject
#     FIRMWARE_ELF ${CMAKE_CURRENT_BINARY_DIR}/firmware.elf
#   )
#
function(setup_firmware_signing_in_project)
    set(options)
    set(oneValueArgs PROJECT_NAME FIRMWARE_ELF)
    set(multiValueArgs)
    
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    if(NOT FIRMWARE_SIGNING_ENABLED)
        return()
    endif()
    
    set(PROJECT_NAME ${ARG_PROJECT_NAME})
    set(FIRMWARE_ELF ${ARG_FIRMWARE_ELF})
    set(FIRMWARE_SIGNED "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}_signed.bin")
    
    # Create signing target
    add_firmware_signing_target(
        TARGET ${PROJECT_NAME}_sign
        INPUT ${FIRMWARE_ELF}
        OUTPUT ${FIRMWARE_SIGNED}
    )
    
    # Create verification test
    add_firmware_verification_check(
        FIRMWARE ${FIRMWARE_SIGNED}
    )
    
    message(STATUS "[Secure Boot] Firmware signing configured for project: ${PROJECT_NAME}")
    
endfunction()

# =============================================================================
# Helper: Check dependencies
# =============================================================================
if(FIRMWARE_SIGNING_ENABLED)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    
    # Check if cryptography module is available
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "import cryptography; import ecdsa"
        RESULT_VARIABLE PYTHON_DEPS_RESULT
        OUTPUT_QUIET
    )
    
    if(NOT PYTHON_DEPS_RESULT EQUAL 0)
        message(WARNING "[Secure Boot] Python cryptography/ecdsa modules not found")
        message(WARNING "              Install with: pip install cryptography ecdsa")
    endif()
    
endif()

message(STATUS "[Secure Boot] CMake firmware signing module loaded")
