#include <Arduino.h>

#include "flashchip.h"
#include "flashserver.h"

FlashServer flashServer;
FlashChip flashChip;

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

  flashServer.init(&flashChip);
  Serial.println("Server has booted!");
}

void loop() {
  delay(1);  // allow the cpu to switch to other tasks
}
