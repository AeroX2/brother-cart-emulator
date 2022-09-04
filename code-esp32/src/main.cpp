#include <Arduino.h>
#include <LittleFS.h>

#include "flashchip.h"
// #include "flashserver.h"

// FlashServer flashServer;
FlashChip flashChip;

#define BUFFER_SIZE 2048

void writeImage() {
  if (flashChip.serialVersion() != 0xBF) {
    Serial.println("Failed to talk with chip");
    return;
  }

  Serial.println("Writing to chip");

  File uploadedFile = LittleFS.open("/image.bin", "r");
  char buffer[BUFFER_SIZE];

  Serial.println("Erasing");
  flashChip.eraseAll();

  Serial.println("Writing...");
  for (int addr = 0; addr < FLASH_CHIP_CAPACITY && addr <= uploadedFile.size();
       addr++) {
    if (addr % BUFFER_SIZE == 0) {
      Serial.print("Currently at: ");
      Serial.println(addr);
      uploadedFile.readBytes(buffer, BUFFER_SIZE);
    }
    byte dat = buffer[addr % 2048];

    if (dat == 0xFF) continue;
    flashChip.writeOneByte(addr, dat);
  }

  Serial.println("Done writing");
}

void verifyImage() {
  if (flashChip.serialVersion() != 0xBF) {
    Serial.println("Failed to talk with chip");
    return;
  }

  File uploadedFile = LittleFS.open("/image.bin", "r");
  char buffer[BUFFER_SIZE];

  Serial.println("Verifying...");
  uploadedFile.seek(0, SeekSet);
  for (int addr = 0; addr < FLASH_CHIP_CAPACITY && addr <= uploadedFile.size();
       addr++) {
    if (addr % BUFFER_SIZE == 0) {
      Serial.print("Currently at: ");
      Serial.println(addr);
      uploadedFile.readBytes(buffer, BUFFER_SIZE);
    }
    byte dat1 = buffer[addr % BUFFER_SIZE];
    byte dat2 = flashChip.readOneByte(addr);

    if (dat1 != dat2) {
      Serial.print("Verification failed at ");
      Serial.print(addr);
      Serial.print(" dat1: ");
      Serial.print(dat1);
      Serial.print(" dat2: ");
      Serial.println(dat2);
      break;
    }
  }

  Serial.println("Done verifying");
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

  // flashServer.init(&flashChip);
  Serial.println("Server has booted!");

  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS failed");
    return;
  }

  delay(3000);

  Serial.print("Write or Verify? (W/V): ");
  while (Serial.available() == 0) {
  }

  char inp = Serial.read();
  if (inp == 'W') {
    writeImage();
  } else if (inp == 'V') {
    verifyImage();
  } else if (inp == 'F') {
    flashChip.writeOneByte(0x100, 'b');
    Serial.println("Fixed");
  } else if (inp == 'D') {
    flashChip.writeOneByte(0x100, 0xFF);
    Serial.println("Unfixed");
  } else if (inp == 'R') {
    Serial.println(flashChip.readOneByte(0x100));
  } else {
    Serial.println("Invalid input");
  }

  // delay(10000);
  // pinMode(23, OUTPUT);
  // digitalWrite(23, LOW);
}

void loop() { delay(1); }
