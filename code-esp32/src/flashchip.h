#ifndef FLASHCHIP_H
#define FLASHCHIP_H

#include <Arduino.h>

#include "CyMCP23016.h"

#define CE 17
#define OE 16
#define WE 4

#define Q0 32
#define Q1 33
#define Q2 25
#define Q3 26
#define Q4 27
#define Q5 14
#define Q6 12
#define Q7 13

#define A16 19
#define A17 18
#define A18 5

#define FLASH_CHIP_CAPACITY 524288

#define CONTROL_PIN(pin, state) \
  {                             \
    boolean* pinType;           \
    if (pin == CE)              \
      pinType = &ceState;       \
    else if (pin == OE)         \
      pinType = &oeState;       \
    else if (pin == WE)         \
      pinType = &weState;       \
    if (*pinType != state) {    \
      *pinType = state;         \
      digitalWrite(pin, state); \
    }                           \
  }

#define DATA_MODE(mod)                                           \
  {                                                              \
    for (uint8_t addr = 0; addr < DATA_ADDRESSES_SIZE; addr++) { \
      pinMode(data_addresses[addr], mod);                        \
    }                                                            \
  }

class FlashChip {
 private:
  boolean ceState;
  boolean oeState;
  boolean weState;

  CyMCP23016 mcp;

  const uint8_t data_addresses[8] = {Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7};
  const uint8_t DATA_ADDRESSES_SIZE = 8;

  void sendCmd(uint32_t addr, uint8_t dat);

 public:
  void init();

  void writeOneByte(uint32_t addr, uint8_t dat);
  uint8_t readOneByte(uint32_t addr);

  void eraseAll();
  uint8_t serialVersion();
};

#endif
