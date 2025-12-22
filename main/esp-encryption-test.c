#define USE_HEX_SW
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "io_helpers/include/io_helpers.h"

void app_main(void) {

    printf("Hello World!\n");

	char buf[65];
	const TickType_t xDelay = 500 / portTICK_PERIOD_MS;

	while(1){
		int len = full_read(STDIN_FILENO, buf, 64);
		buf[64] = 0;
		printf("len == %d", len);
		if (len >= 0) {
			printf("You typed: %s", buf);
		}
		vTaskDelay( xDelay );
	}




}
