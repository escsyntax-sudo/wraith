#pragma once
#include <Arduino.h>

void log_init();
void log_print(const char *fmt, ...);
void log_clear();
String log_json();
