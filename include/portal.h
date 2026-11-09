#pragma once
#include <Arduino.h>

void portal_begin();
bool portal_start(const String &ssid);
void portal_stop();
void portal_tick();
bool portal_active();
String portal_ssid();
uint16_t portal_cred_count();
String portal_creds_json();
