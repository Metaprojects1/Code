/****************************************************************************
 *
 *   Copyright (c) 2020-2021 PX4 Development Team. All rights reserved.
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
 * @file bootloader_main.c
 *
 * FMU-specific early startup code for bootloader
*/

#include "board_config.h"
#include "bl.h"

#include <nuttx/config.h>
#include <nuttx/board.h>
#include <chip.h>
#include <stm32_uart.h>
#include <arch/board/board.h>
#include "arm_internal.h"
#include <px4_platform_common/init.h>

/* Secure boot integration */
#include "secure_boot.h"
#include "secure_boot_integration.h"

extern int sercon_main(int c, char **argv);

__EXPORT void board_on_reset(int status) {}

__EXPORT void stm32_boardinitialize(void)
{
	/* configure USB interfaces */
	stm32_configgpio(GPIO_OTGFS_VBUS);
}

__EXPORT int board_app_initialize(uintptr_t arg)
{
	/* Initialize secure boot system */
	secure_boot_bootloader_init();
	
	/* Verify application firmware before booting */
	if (!secure_boot_verify_application()) {
		/* Firmware verification failed - log error and halt */
		secure_boot_result_t error = secure_boot_get_last_error();
		
#ifdef DEBUG
		/* Output error for debugging (if UART available) */
		printf("SECURITY: Firmware verification failed (error: %u)\n", (unsigned)error);
		printf("SECURITY: %s\n", secure_boot_strerror(error));
		
		/* Flash LED pattern indicating secure boot failure */
		for (int i = 0; i < 5; i++) {
			led_on(LED_BOOTLOADER);
			delay(100);
			led_off(LED_BOOTLOADER);
			delay(100);
		}
#endif
		
		/* Call failure handler (typically halts system) */
		secure_boot_failure_handler(error);
		
		/* Never reached */
		return -1;
	}
	
#ifdef DEBUG
	printf("SECURITY: Firmware verification successful - booting application\n");
#endif

	return 0;
}

void board_late_initialize(void)
{
	sercon_main(0, NULL);
}

extern void sys_tick_handler(void);
void board_timerhook(void)
{
	sys_tick_handler();
}
