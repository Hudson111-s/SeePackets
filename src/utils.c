#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#include "utils.h"

void print_payload(const uint8_t *data, size_t data_size) {
    if (data_size <= 0) {
        printf("No payload.\n");
        return;
    } 

    printf("--- Payload size (%ld) ---\n", data_size);
    for (int i = 0; i < data_size; i += 16) {
        printf("%04X ", i);

        // Print hex.
        for (int j = 0; j < 16; j++) {
            if (i + j < data_size) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        } 

        printf(" | ");

        // Print byte/char if readable.
        for (int j = 0; j < 16; j++) {
            if (i + j < data_size) {
                char byte = data[i + j];
                printf("%c", isprint(byte) ? byte : '.');
            }
        }

        printf("\n");
    }

    printf("-------------------------------\n");
}