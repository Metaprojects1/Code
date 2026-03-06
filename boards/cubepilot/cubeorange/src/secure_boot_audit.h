/****************************************************************************
 *
 *   Copyright (c) 2024 PX4 Development Team. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name PX4 nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/**
 * @file secure_boot_audit.h
 *
 * Audit Logging for Secure Boot
 * IEC 62443-4-1 Compliance: Logs security events to persistent storage
 * 
 * Supports:
 * - Firmware verification attempts (success/failure)
 * - Signature validation results
 * - Boot decisions
 * - Key updates
 * - Security violations
 */
#ifndef SECURE_BOOT_AUDIT_H
#define SECURE_BOOT_AUDIT_H

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* ==================== Audit Log Configuration ==================== */

/* Log storage location (STM32H7 protected flash sector) */
#define AUDIT_LOG_BASE_ADDRESS  0x081E0000  /* Sector 6 (128KB) */
#define AUDIT_LOG_MAX_SIZE      0x20000     /* 128KB total */
#define AUDIT_LOG_RECORD_SIZE   64          /* 64 bytes per record */
#define AUDIT_LOG_MAX_RECORDS   (AUDIT_LOG_MAX_SIZE / AUDIT_LOG_RECORD_SIZE)  /* 2048 records */

/* ==================== Audit Event Types ==================== */

typedef enum {
	AUDIT_EVT_INVALID               = 0x00,
	AUDIT_EVT_FIRMWARE_VERIFY_START = 0x10,  /* Firmware verification started */
	AUDIT_EVT_FIRMWARE_VERIFY_PASS  = 0x11,  /* Firmware verification passed */
	AUDIT_EVT_FIRMWARE_VERIFY_FAIL  = 0x12,  /* Firmware verification failed */
	AUDIT_EVT_SIGNATURE_VALID       = 0x20,  /* Signature validation passed */
	AUDIT_EVT_SIGNATURE_INVALID     = 0x21,  /* Signature validation failed */
	AUDIT_EVT_HASH_VALID            = 0x22,  /* Hash verification passed */
	AUDIT_EVT_HASH_INVALID          = 0x23,  /* Hash verification failed */
	AUDIT_EVT_BOOT_AUTHORIZED       = 0x30,  /* Boot authorized */
	AUDIT_EVT_BOOT_DENIED           = 0x31,  /* Boot denied - security check failed */
	AUDIT_EVT_BOOT_EXECUTED         = 0x32,  /* Jumping to application */
	AUDIT_EVT_KEY_LOADED            = 0x40,  /* Public key loaded */
	AUDIT_EVT_KEY_STORED            = 0x41,  /* Public key stored */
	AUDIT_EVT_KEY_UPDATED           = 0x42,  /* Public key updated */
	AUDIT_EVT_ROLLBACK_PREVENTED    = 0x50,  /* Downgrade attack prevented */
	AUDIT_EVT_TAMPER_DETECTED       = 0x60,  /* Tamper detection triggered */
	AUDIT_EVT_CRYPT_ERROR           = 0x70,  /* Cryptographic operation failed */
	AUDIT_EVT_MEMORY_ERROR          = 0x71,  /* Memory access error */
	AUDIT_EVT_HARDWARE_ERROR        = 0x72,  /* Hardware error */
	AUDIT_EVT_DEBUG_PORT_DISABLE    = 0x80,  /* Debug port disabled */
	AUDIT_EVT_SYSTEM_HALT           = 0x90,  /* System security halt */
} audit_event_type_t;

/* ==================== Audit Record Structure ==================== */

/**
 * @brief Single audit log record (64 bytes)
 * 
 * Layout:
 * Offset  Size      Field
 * ------  ----      -----
 *   0     4         Timestamp (seconds since epoch)
 *   4     1         Event type
 *   5     1         Event severity (0=info, 1=warning, 2=error, 3=critical)
 *   6     2         Error code / additional data
 *   8     4         Firmware size (if applicable)
 *  12     4         Firmware CRC32 (if applicable)
 *  16    32         Hash value (SHA256, partial)
 *  48     8         Reserved for future use
 *  56     4         Record CRC32 (for integrity)
 *  60     4         Sequence number (for replay detection)
 */
typedef struct __attribute__((packed)) {
	uint32_t timestamp;      /* Unix timestamp */
	uint8_t  event_type;     /* Event type */
	uint8_t  severity;       /* 0=info, 1=warning, 2=error, 3=critical */
	uint16_t error_code;     /* Error code or additional data */
	uint32_t firmware_size;  /* Firmware size if applicable */
	uint32_t firmware_crc32; /* Firmware CRC if applicable */
	uint8_t  hash[32];       /* Hash value (partial SHA256) */
	uint64_t reserved;       /* Reserved for future use */
	uint32_t record_crc32;   /* CRC32 of this record for integrity */
	uint32_t sequence;       /* Sequence number */
} __attribute__((packed)) audit_record_t;

/* ==================== Severity Levels ==================== */

typedef enum {
	AUDIT_SEVERITY_INFO     = 0,  /* Informational */
	AUDIT_SEVERITY_WARNING  = 1,  /* Warning - recoverable */
	AUDIT_SEVERITY_ERROR    = 2,  /* Error but system continues */
	AUDIT_SEVERITY_CRITICAL = 3,  /* Critical - system must halt */
} audit_severity_t;

/* ==================== Audit Log API ==================== */

/**
 * @brief Initialize audit logging system
 * 
 * @return 0 on success, -1 on error
 */
int audit_log_init(void);

/**
 * @brief Record an audit event
 * 
 * @param event_type Type of event to log
 * @param severity   Severity level
 * @param error_code Error code (optional)
 * @param fw_size    Firmware size (optional, 0 if not applicable)
 * @param fw_crc32   Firmware CRC (optional, 0 if not applicable)
 * @param hash       Hash data (optional, NULL if not applicable)
 * 
 * @return 0 on success, -1 on error
 */
int audit_log_record(audit_event_type_t event_type,
                     audit_severity_t severity,
                     uint16_t error_code,
                     uint32_t fw_size,
                     uint32_t fw_crc32,
                     const uint8_t *hash);

/**
 * @brief Get total number of audit log records
 * 
 * @return Number of records in log, or -1 on error
 */
int audit_log_get_record_count(void);

/**
 * @brief Read an audit log record
 * 
 * @param index  Record index (0-based)
 * @param record Pointer to record buffer
 * 
 * @return 0 on success, -1 on error
 */
int audit_log_read_record(uint32_t index, audit_record_t *record);

/**
 * @brief Clear audit log (secure erase)
 * 
 * Overwrites entire log with random data before erasing.
 * Requires elevated privileges.
 * 
 * @return 0 on success, -1 on error
 */
int audit_log_clear(void);

/**
 * @brief Export audit log to buffer
 * 
 * @param buffer Output buffer
 * @param buffer_size Size of buffer
 * @param format Export format (0=binary, 1=CSV, 2=JSON)
 * 
 * @return Number of bytes written, or -1 on error
 */
int audit_log_export(uint8_t *buffer, uint32_t buffer_size, uint8_t format);

/**
 * @brief Verify audit log integrity
 * 
 * Checks CRC32 of all records and proper sequence.
 * 
 * @return 0 if log is valid, -1 if corrupted or invalid
 */
int audit_log_verify_integrity(void);

/**
 * @brief Get audit log status
 * 
 * @return Bitmask:
 *         Bit 0: Log initialized
 *         Bit 1: Log nearly full (>90%)
 *         Bit 2: Log corruption detected
 *         Bit 3: Flash write errors
 */
uint32_t audit_log_get_status(void);

/**
 * @brief Get latest security event
 * 
 * @param record Pointer to record buffer
 * 
 * @return 0 on success, -1 if no records
 */
int audit_log_get_latest(audit_record_t *record);

/**
 * @brief Get events of specific type
 * 
 * @param event_type Event type to search for
 * @param max_records Maximum records to return
 * @param records Output buffer for records
 * 
 * @return Number of matching records found
 */
int audit_log_get_events_by_type(audit_event_type_t event_type,
                                  uint32_t max_records,
                                  audit_record_t *records);

/**
 * @brief Get security failure count
 * 
 * Returns total number of verification failures.
 * Useful for intrusion detection.
 * 
 * @return Count of failed verifications
 */
uint32_t audit_log_get_failure_count(void);

/**
 * @brief Get last boot result
 * 
 * @return 0 if last boot succeeded, non-zero if failed
 */
int audit_log_get_last_boot_status(void);

/* ==================== Helper Macros ==================== */

/**
 * @brief Convenience macro to log firmware verification
 */
#define AUDIT_LOG_FW_VERIFY_PASS(fw_size, fw_crc, hash) \
	audit_log_record(AUDIT_EVT_FIRMWARE_VERIFY_PASS, \
	                  AUDIT_SEVERITY_INFO, 0, fw_size, fw_crc, hash)

#define AUDIT_LOG_FW_VERIFY_FAIL(error, fw_size, fw_crc) \
	audit_log_record(AUDIT_EVT_FIRMWARE_VERIFY_FAIL, \
	                  AUDIT_SEVERITY_ERROR, error, fw_size, fw_crc, NULL)

/**
 * @brief Log boot authorization
 */
#define AUDIT_LOG_BOOT_OK() \
	audit_log_record(AUDIT_EVT_BOOT_AUTHORIZED, \
	                  AUDIT_SEVERITY_INFO, 0, 0, 0, NULL)

#define AUDIT_LOG_BOOT_DENY(reason) \
	audit_log_record(AUDIT_EVT_BOOT_DENIED, \
	                  AUDIT_SEVERITY_CRITICAL, reason, 0, 0, NULL)

#endif /* SECURE_BOOT_AUDIT_H */
