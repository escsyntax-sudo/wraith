#pragma once
#include "types.h"

void sniffer_begin();
void sniffer_start_scan(uint8_t channel, bool hop);
void sniffer_start_capture(uint8_t channel, bool hop);
void sniffer_stop();
void sniffer_tick();

bool sniffer_active();
bool sniffer_is_capturing();
uint8_t sniffer_channel();
uint32_t sniffer_frame_total();
uint16_t sniffer_pending_drops();

uint16_t ap_count();
bool ap_at(uint16_t index, ApRecord *out);
int ap_index_of(const uint8_t *bssid);

uint16_t client_count();
bool client_at(uint16_t index, ClientRecord *out);

uint16_t handshake_count();
bool handshake_at(uint16_t index, HandshakeRecord *out);

void sniffer_clear_tables();
const CaptureStats &capture_stats();
