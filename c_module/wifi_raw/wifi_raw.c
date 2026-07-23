/*
 * wifi_raw.c — MicroPython C module exposing ESP-IDF Wi-Fi promiscuous
 *              mode and raw 802.11 frame injection for ESP32-S3.
 *
 * Part of ESP32-S3 Marauder — Wi-Fi Security Testing Tool
 *
 * WARNING: This module is intended for AUTHORIZED penetration testing and
 * educational purposes ONLY. Unauthorized use is illegal.
 */

#include <string.h>
#include "py/runtime.h"
#include "py/obj.h"
#include "py/objstr.h"
#include "py/mphal.h"
#include "py/mperrno.h"
#include "py/gc.h"

#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ------------------------------------------------------------------ */
/* Ring buffer for passing packets from WiFi task to MicroPython */
/* ------------------------------------------------------------------ */

#define RING_SIZE 64 /* number of slots */
#define MAX_PKT_LEN 512 /* truncate packets longer than this */

typedef struct {
  uint8_t data[MAX_PKT_LEN];
  uint16_t len;
  uint8_t pkt_type; /* wifi_promiscuous_pkt_type_t */
  int8_t rssi;
} ring_entry_t;

static ring_entry_t ring_buf[RING_SIZE];
static volatile int ring_head = 0; /* next write position (producer) */
static volatile int ring_tail = 0; /* next read position (consumer) */
static volatile bool drain_scheduled = false;
static portMUX_TYPE ring_mux = portMUX_INITIALIZER_UNLOCKED;

// Store GC root reference to callback to prevent garbage collection
static mp_obj_t py_callback = MP_OBJ_NULL;
static bool promisc_active = false;
static bool wifi_inited = false;

/* ---- ring helpers ------------------------------------------------- */

static inline int ring_next(int idx) { return (idx + 1) % RING_SIZE; }

static inline bool ring_full(void) {
  return ring_next(ring_head) == ring_tail;
}

static inline bool ring_empty(void) { return ring_head == ring_tail; }

/* ------------------------------------------------------------------ */
/* Forward declarations */
/* ------------------------------------------------------------------ */

static mp_obj_t drain_ring(mp_obj_t _unused);
MP_DEFINE_CONST_FUN_OBJ_1(drain_ring_obj, drain_ring);

/* ------------------------------------------------------------------ */
/* Promiscuous-mode callback (runs in WiFi task — NOT MicroPython) */
/* ------------------------------------------------------------------ */

static void IRAM_ATTR promisc_rx_cb(void *buf,
                                    wifi_promiscuous_pkt_type_t type) {
  if (py_callback == MP_OBJ_NULL || py_callback == mp_const_none) return;

  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint16_t len = pkt->rx_ctrl.sig_len;
  if (len > MAX_PKT_LEN) len = MAX_PKT_LEN;

  bool need_schedule = false;

  taskENTER_CRITICAL(&ring_mux);
  if (!ring_full()) {
    ring_entry_t *e = &ring_buf[ring_head];
    memcpy(e->data, pkt->payload, len);
    e->len = len;
    e->pkt_type = (uint8_t)type;
    e->rssi = pkt->rx_ctrl.rssi;
    ring_head = ring_next(ring_head);
  }
  if (!drain_scheduled) {
    drain_scheduled = true;
    need_schedule = true;
  }
  taskEXIT_CRITICAL(&ring_mux);

  if (need_schedule) {
    mp_sched_schedule(MP_OBJ_FROM_PTR(&drain_ring_obj), mp_const_none);
  }
}

/* ------------------------------------------------------------------ */
/* Drain function — runs in MicroPython thread via mp_sched_schedule */
/* ------------------------------------------------------------------ */

static mp_obj_t drain_ring(mp_obj_t _unused) {
  while (!ring_empty()) {
    ring_entry_t e;

    taskENTER_CRITICAL(&ring_mux);
    if (ring_empty()) {
      taskEXIT_CRITICAL(&ring_mux);
      break;
    }
    memcpy(&e, &ring_buf[ring_tail], sizeof(ring_entry_t));
    ring_tail = ring_next(ring_tail);
    taskEXIT_CRITICAL(&ring_mux);

    if (py_callback != MP_OBJ_NULL && py_callback != mp_const_none) {
      mp_obj_t args[3] = {
          mp_obj_new_bytes(e.data, e.len),
          mp_obj_new_int(e.pkt_type),
          mp_obj_new_int(e.rssi),
      };
      nlr_buf_t nlr;
      if (nlr_push(&nlr) == 0) {
        mp_call_function_n_kw(py_callback, 3, 0, args);
        nlr_pop();
      } else {
        // Exception handling
      }
    }
  }

  taskENTER_CRITICAL(&ring_mux);
  drain_scheduled = false;
  taskEXIT_CRITICAL(&ring_mux);

  return mp_const_none;
}

/* ================================================================== */
/* Python-visible functions */
/* ================================================================== */

/* ---- init() ------------------------------------------------------- */

static mp_obj_t wifi_raw_init(void) {
  if (wifi_inited) return mp_const_none;

  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_flash_init();
  }

  esp_netif_init();
  esp_event_loop_create_default();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  wifi_inited = true;
  py_callback = MP_OBJ_NULL;
  drain_scheduled = false;
  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(wifi_raw_init_obj, wifi_raw_init);

/* ---- promiscuous_start(callback, filter_mask=0xF) ----------------- */

static mp_obj_t wifi_raw_promiscuous_start(size_t n_args,
                                            const mp_obj_t *args) {
  if (!wifi_inited) {
    mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("call init() first"));
  }

  py_callback = args[0];

  uint32_t mask = 0x0F;
  if (n_args > 1) {
    mask = mp_obj_get_int(args[1]);
  }

  wifi_promiscuous_filter_t filt = {.filter_mask = 0};
  if (mask & 1) filt.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
  if (mask & 2) filt.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
  if (mask & 4) filt.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
  if (mask & 8) filt.filter_mask |= WIFI_PROMIS_FILTER_MASK_MISC;

  taskENTER_CRITICAL(&ring_mux);
  ring_head = 0;
  ring_tail = 0;
  drain_scheduled = false;
  taskEXIT_CRITICAL(&ring_mux);

  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(promisc_rx_cb);
  esp_wifi_set_promiscuous(true);
  promisc_active = true;

  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(wifi_raw_promiscuous_start_obj, 1,
                                            2, wifi_raw_promiscuous_start);

/* ---- promiscuous_stop() ------------------------------------------- */

static mp_obj_t wifi_raw_promiscuous_stop(void) {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  py_callback = MP_OBJ_NULL;
  promisc_active = false;

  taskENTER_CRITICAL(&ring_mux);
  ring_head = 0;
  ring_tail = 0;
  drain_scheduled = false;
  taskEXIT_CRITICAL(&ring_mux);

  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(wifi_raw_promiscuous_stop_obj,
                                  wifi_raw_promiscuous_stop);

/* ---- send_raw(packet_bytes) -> bool ------------------------------- */

static mp_obj_t wifi_raw_send_raw(mp_obj_t pkt_in) {
  if (!wifi_inited) {
    mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("call init() first"));
  }

  mp_buffer_info_t bufinfo;
  mp_get_buffer_raise(pkt_in, &bufinfo, MP_BUFFER_READ);

  esp_err_t err =
      esp_wifi_80211_tx(WIFI_IF_STA, bufinfo.buf, bufinfo.len, false);

  return mp_obj_new_bool(err == ESP_OK);
}
static MP_DEFINE_CONST_FUN_OBJ_1(wifi_raw_send_raw_obj, wifi_raw_send_raw);

/* ---- set_channel(ch) ---------------------------------------------- */

static mp_obj_t wifi_raw_set_channel(mp_obj_t ch_in) {
  int ch = mp_obj_get_int(ch_in);
  if (ch < 1 || ch > 14) {
    mp_raise_ValueError(MP_ERROR_TEXT("channel must be 1-14"));
  }
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(wifi_raw_set_channel_obj,
                                  wifi_raw_set_channel);

/* ---- get_channel() -> int ----------------------------------------- */

static mp_obj_t wifi_raw_get_channel(void) {
  uint8_t primary;
  wifi_second_chan_t second;
  esp_wifi_get_channel(&primary, &second);
  return mp_obj_new_int(primary);
}
static MP_DEFINE_CONST_FUN_OBJ_0(wifi_raw_get_channel_obj,
                                  wifi_raw_get_channel);

/* ================================================================== */
/* Module table */
/* ================================================================== */

static const mp_rom_map_elem_t wifi_raw_module_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR__wifi_raw)},
    {MP_ROM_QSTR(MP_QSTR_init), MP_ROM_PTR(&wifi_raw_init_obj)},
    {MP_ROM_QSTR(MP_QSTR_promiscuous_start),
     MP_ROM_PTR(&wifi_raw_promiscuous_start_obj)},
    {MP_ROM_QSTR(MP_QSTR_promiscuous_stop),
     MP_ROM_PTR(&wifi_raw_promiscuous_stop_obj)},
    {MP_ROM_QSTR(MP_QSTR_send_raw), MP_ROM_PTR(&wifi_raw_send_raw_obj)},
    {MP_ROM_QSTR(MP_QSTR_set_channel), MP_ROM_PTR(&wifi_raw_set_channel_obj)},
    {MP_ROM_QSTR(MP_QSTR_get_channel), MP_ROM_PTR(&wifi_raw_get_channel_obj)},
};
static MP_DEFINE_CONST_DICT(wifi_raw_module_globals,
                            wifi_raw_module_globals_table);

const mp_obj_module_t mp_module_wifi_raw = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&wifi_raw_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR__wifi_raw, mp_module_wifi_raw);
