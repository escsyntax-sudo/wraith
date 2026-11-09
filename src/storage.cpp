#include "storage.h"
#include <LittleFS.h>
#include <SPI.h>
#include <SD.h>
#include "config.h"

static bool g_sd = false;
static bool g_ready = false;
static const char *g_kind = "none";

static void ensure_dirs(fs::FS &fs) {
  if (!fs.exists(CAPTURE_DIR)) fs.mkdir(CAPTURE_DIR);
}

bool storage_begin() {
  // LittleFS always mounts: it carries the control panel assets even when an
  // SD card is present and takes over capture storage.
  bool littlefs_ok = LittleFS.begin(true);
  if (littlefs_ok) ensure_dirs(LittleFS);

#if SD_ENABLED
  SPI.begin(SD_SCK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);
  if (SD.begin(SD_CS_PIN, SPI, 20000000)) {
    g_sd = true;
    g_ready = true;
    g_kind = "sd";
    ensure_dirs(SD);
    return true;
  }
  SD.end();
#endif

  g_sd = false;
  g_ready = littlefs_ok;
  g_kind = littlefs_ok ? "littlefs" : "none";
  return g_ready;
}

bool storage_ready() { return g_ready; }

fs::FS &storage_fs() { return g_sd ? static_cast<fs::FS &>(SD) : static_cast<fs::FS &>(LittleFS); }

const char *storage_kind() { return g_kind; }

String capture_path(const char *prefix) {
  char buf[48];
  snprintf(buf, sizeof(buf), "%s/%s_%lu.pcap", CAPTURE_DIR, prefix,
           static_cast<unsigned long>(millis()));
  return String(buf);
}

bool PcapWriter::open(const String &path) {
  if (!g_ready) return false;
  if (_open) close();
  _file = storage_fs().open(path, FILE_WRITE);
  if (!_file) return false;
  _path = path;
  _bytes = 0;
  _open = true;

  // libpcap global header, little endian, link type 127 (IEEE 802.11)
  uint8_t header[24];
  const uint32_t magic = 0xa1b2c3d4;
  const uint16_t vmaj = 2, vmin = 4;
  const uint32_t zone = 0, sigfigs = 0, snaplen = 65535, network = 127;
  memcpy(header + 0, &magic, 4);
  memcpy(header + 4, &vmaj, 2);
  memcpy(header + 6, &vmin, 2);
  memcpy(header + 8, &zone, 4);
  memcpy(header + 12, &sigfigs, 4);
  memcpy(header + 16, &snaplen, 4);
  memcpy(header + 20, &network, 4);
  _file.write(header, sizeof(header));
  _bytes = sizeof(header);
  return true;
}

void PcapWriter::write(const uint8_t *data, uint16_t len, uint32_t sec, uint32_t usec) {
  if (!_open || !_file) return;
  uint8_t hdr[16];
  uint32_t incl = len;
  uint32_t orig = len;
  memcpy(hdr + 0, &sec, 4);
  memcpy(hdr + 4, &usec, 4);
  memcpy(hdr + 8, &incl, 4);
  memcpy(hdr + 12, &orig, 4);
  _file.write(hdr, sizeof(hdr));
  _file.write(data, len);
  _bytes += sizeof(hdr) + len;
}

void PcapWriter::close() {
  if (_file) _file.close();
  _open = false;
}
