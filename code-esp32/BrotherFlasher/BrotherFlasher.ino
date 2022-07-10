#include <Arduino.h>
#include "flashchip.h"

FlashChip flashChip;

void writeFileToChip() {
  
}

void verifyFileOnChip() {
  
}

void setup() {
    Serial.begin(115200);

    delay(3000);
    flashChip.init();
    
    uint8_t serial = flashChip.serialVersion();
    if (serial != 0xBF) {
      Serial.print("Serial returned: ");
      Serial.println(serial, HEX);
      exit(0);
    }

    Serial.println("Clearing chip");
    flashChip.eraseAll();
}

void loop() {
}
