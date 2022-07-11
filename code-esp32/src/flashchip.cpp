#include "flashchip.h"

void FlashChip::init() {
  pinMode(CE, OUTPUT);
  pinMode(OE, OUTPUT);
  pinMode(WE, OUTPUT);

  pinMode(A16, OUTPUT);
  pinMode(A17, OUTPUT);
  pinMode(A18, OUTPUT);
  digitalWrite(A16, LOW);
  digitalWrite(A17, LOW);
  digitalWrite(A18, LOW);

  mcp.begin();
  for (int i = 0; i <= MCP23016_PIN_GPIO1_7; i++) {
    while (!mcp.detected()) {
      Serial.println("Waiting for MCP");
      delay(100);
    }
    mcp.pinMode(i, OUTPUT);
  }

  while (!mcp.detected()) {
    Serial.println("Waiting for MCP");
    delay(100);
  }
}

void FlashChip::sendCmd(uint32_t addr, uint8_t dat) {
  DATA_MODE(OUTPUT);
  CONTROL_PIN(CE, LOW);
  CONTROL_PIN(OE, HIGH);
  CONTROL_PIN(WE, HIGH);

  mcp.writeAllPins(addr);
  digitalWrite(A16, addr >> 16 & 1);
  digitalWrite(A17, addr >> 17 & 1);
  digitalWrite(A18, addr >> 18 & 1);

  CONTROL_PIN(WE, LOW);

  for (uint8_t addr = 0; addr < DATA_ADDRESSES_SIZE; addr++) {
    digitalWrite(data_addresses[addr], (dat >> addr) & 1);
  }

  CONTROL_PIN(WE, HIGH);
}

void FlashChip::writeOneByte(uint32_t addr, uint8_t dat) {
  if (addr >= FLASH_CHIP_CAPACITY) {
    Serial.println("Address exceeds flash chip capacity");
    return;
  }

  CONTROL_PIN(CE, LOW);
  CONTROL_PIN(OE, HIGH);

  sendCmd(0x5555, 0xAA);
  sendCmd(0x2AAA, 0x55);
  sendCmd(0x5555, 0xA0);
  sendCmd(addr, dat);

  CONTROL_PIN(CE, HIGH);
  delayMicroseconds(20);
}

uint8_t FlashChip::readOneByte(uint32_t addr) {
  if (addr >= FLASH_CHIP_CAPACITY) {
    Serial.println("Address exceeds flash chip capacity");
    return 0;
  }

  DATA_MODE(INPUT);

  CONTROL_PIN(CE, LOW);
  CONTROL_PIN(OE, LOW);

  mcp.writeAllPins(addr);
  delayMicroseconds(1);

  uint8_t dat = 0;
  for (uint8_t addr = 0; addr < DATA_ADDRESSES_SIZE; addr++) {
    dat |= digitalRead(data_addresses[addr]) << addr;
  }

  return dat;
}

void FlashChip::eraseAll() {
  sendCmd(0x5555, 0xAA);
  sendCmd(0x2AAA, 0x55);
  sendCmd(0x5555, 0x80);
  sendCmd(0x5555, 0xAA);
  sendCmd(0x2AAA, 0x55);
  sendCmd(0x5555, 0x10);

  delay(200);
}

uint8_t FlashChip::serialVersion() {
  sendCmd(0x5555, 0xAA);
  sendCmd(0x2AAA, 0x55);
  sendCmd(0x5555, 0x90);

  uint8_t serial = readOneByte(0);

  sendCmd(0x5555, 0xAA);
  sendCmd(0x2AAA, 0x55);
  sendCmd(0x5555, 0xF0);

  return serial;
}
