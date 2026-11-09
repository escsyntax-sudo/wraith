#pragma once
#include <Arduino.h>

void beacon_begin();
bool beacon_start(uint32_t max_frames, const String &ssid, uint8_t channel);
void beacon_stop();
void beacon_tick();
bool beacon_active();
uint32_t beacon_sent();
