#pragma once
#include "types.h"

void deauth_begin();
bool deauth_start(const uint8_t *bssid, const uint8_t *client, uint8_t channel, uint16_t reason,
                  bool continuous, uint32_t max_frames);
void deauth_stop();
void deauth_tick();
bool deauth_active();
const AttackConfig &deauth_config();
