#pragma once
#include <Arduino.h>
#include <FS.h>

bool storage_begin();
bool storage_ready();
fs::FS &storage_fs();
const char *storage_kind();

class PcapWriter {
 public:
  bool open(const String &path);
  void write(const uint8_t *data, uint16_t len, uint32_t sec, uint32_t usec);
  void close();
  bool is_open() const { return _open; }
  uint32_t bytes() const { return _bytes; }
  const String &path() const { return _path; }

 private:
  File _file;
  String _path;
  uint32_t _bytes = 0;
  bool _open = false;
};

String capture_path(const char *prefix);
