#pragma once
#include <Arduino.h>
#include <esp_wifi.h>
#include "types.h"

void wifi_radio_init();
void wifi_set_channel(uint8_t channel);
uint8_t wifi_freq_to_channel(uint16_t freq);
uint16_t wifi_channel_to_freq(uint8_t channel);
String wifi_mac_str(const uint8_t *mac);
bool wifi_parse_mac(const String &text, uint8_t out[6]);
bool wifi_mac_multicast(const uint8_t *mac);
bool wifi_mac_zero(const uint8_t *mac);
bool wifi_mac_equal(const uint8_t *a, const uint8_t *b);
const char *wifi_enc_label(uint8_t enc);
const char *wifi_mode_label(OpMode mode);
void wifi_random_mac(uint8_t *mac);
