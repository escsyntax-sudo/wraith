#include "log.h"
#include <stdarg.h>
#include "config.h"
#include "types.h"

static LogRing g_log;

void log_init() {
  memset(&g_log, 0, sizeof(g_log));
}

void log_print(const char *fmt, ...) {
  char line[96];
  va_list args;
  va_start(args, fmt);
  vsnprintf(line, sizeof(line), fmt, args);
  va_end(args);

  uint8_t slot = g_log.head;
  strncpy(g_log.lines[slot], line, sizeof(g_log.lines[slot]) - 1);
  g_log.lines[slot][sizeof(g_log.lines[slot]) - 1] = '\0';
  g_log.head = static_cast<uint8_t>((g_log.head + 1) % MAX_LOG_LINES);
  if (g_log.count < MAX_LOG_LINES) g_log.count++;

  Serial.println(line);
}

void log_clear() {
  memset(&g_log, 0, sizeof(g_log));
}

String log_json() {
  String out = "[";
  uint8_t start = static_cast<uint8_t>((g_log.head + MAX_LOG_LINES - g_log.count) % MAX_LOG_LINES);
  for (uint8_t i = 0; i < g_log.count; i++) {
    uint8_t idx = static_cast<uint8_t>((start + i) % MAX_LOG_LINES);
    if (i) out += ",";
    out += "\"";
    for (const char *p = g_log.lines[idx]; *p; p++) {
      char c = *p;
      if (c == '"' || c == '\\') out += "\\";
      out += c;
    }
    out += "\"";
  }
  out += "]";
  return out;
}
