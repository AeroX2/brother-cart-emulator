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
      while(!mcp.detected()) {
        Serial.println("Waiting for MCP");
        delay(100);
      }
      mcp.pinMode(i, OUTPUT);
    }
  
    while(!mcp.detected()) {
      Serial.println("Waiting for MCP");
      delay(100);
    }
}

void FlashChip::sendCmd(uint16_t addr, uint8_t dat) {
  DATA_MODE(OUTPUT);
  CONTROL_PIN(CE, LOW);
  CONTROL_PIN(OE, HIGH);
  CONTROL_PIN(WE, HIGH);
  
  mcp.writeAllPins(addr);
  
  CONTROL_PIN(WE, LOW);
  
  for (uint8_t address = 0; address < DATA_ADDRESSES_SIZE; address++) {
    digitalWrite(data_addresses[address], (dat >> address) & 1);
  }
  
  CONTROL_PIN(WE, HIGH);
}

void FlashChip::writeOneByte(uint16_t addr, uint8_t dat) {
  CONTROL_PIN(CE,LOW);
  CONTROL_PIN(OE,HIGH);
  
  sendCmd(0x5555,0xAA);
  sendCmd(0x2AAA,0x55);
  sendCmd(0x5555,0xA0);
  sendCmd(addr,dat);

  CONTROL_PIN(CE,HIGH);
  delayMicroseconds(20);
}

uint8_t FlashChip::readOneByte(uint16_t addr) {
  DATA_MODE(INPUT);
  
  CONTROL_PIN(CE,LOW);
  CONTROL_PIN(OE,LOW);
  
  mcp.writeAllPins(addr);
  delayMicroseconds(1);
  
  uint8_t dat = 0;
  for (uint8_t address = 0; address < DATA_ADDRESSES_SIZE; address++) {
    dat |= digitalRead(data_addresses[address]) << address;
  }
  
  return dat;
}

void FlashChip::eraseAll() {
    sendCmd(0x5555,0xAA);
    sendCmd(0x2AAA,0x55);
    sendCmd(0x5555,0x80);
    sendCmd(0x5555,0xAA);
    sendCmd(0x2AAA,0x55);
    sendCmd(0x5555,0x10);
    
    delay(200);
}

uint8_t FlashChip::serialVersion() {
  sendCmd(0x5555,0xAA);
  sendCmd(0x2AAA,0x55);
  sendCmd(0x5555,0x90);
  
  uint8_t serial = readOneByte(0);

  sendCmd(0x5555,0xAA);
  sendCmd(0x2AAA,0x55);
  sendCmd(0x5555,0xF0);

  return serial;
}
