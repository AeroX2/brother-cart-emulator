#include "flashserver.h"

FlashChip* FlashServer::flashChip;
File FlashServer::uploadedFile;
const char* FlashServer::status;
bool FlashServer::fileReady;

void FlashServer::init(FlashChip *_flashChip) {
  flashChip = _flashChip;

  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS failed");
    return;
  }

  WiFi.softAP("BrotherFlasher");

  webServer.on("/", HTTP_GET, FlashServer::handleRoot);
  webServer.on("/", HTTP_POST, [](AsyncWebServerRequest* request){
    request->send(200);
  }, FlashServer::handleFileUpload);
  webServer.on("/write", HTTP_POST, FlashServer::handleWriteImage);
  webServer.on("/status", HTTP_GET, FlashServer::handleStatus);

  webServer.onFileUpload(FlashServer::handleFileUpload);
  webServer.begin();

  status = "Hello!";
}

void FlashServer::handleRoot(AsyncWebServerRequest *request) {
  request->send_P(200, "text/html", index_html);
}

void FlashServer::writeImage(void *parameter) {
  if (flashChip->serialVersion() != 0xBF) {
    Serial.println("Failed to talk with chip");
    status = "AGHHHHHH";
    //vTaskDelete(NULL);
    return;
  }

  Serial.println("Writing to chip");
  status = "Writing image";

  uploadedFile = LittleFS.open("/image.bin", "w");
  char buffer[1];

  Serial.println("Erasing");
  flashChip->eraseAll();
  for (int addr = 0; addr < FLASH_CHIP_CAPACITY && addr < uploadedFile.size(); addr++) {
    uploadedFile.readBytes(buffer, 1);
    byte dat = buffer[0];

    if (dat == 0xFF) continue;
    flashChip->writeOneByte(addr, dat);
  }

  Serial.println("Finishied writing, now verifying");
  status = "Verifying data";
  uploadedFile.seek(0, SeekSet);
  for (int addr = 0; addr < FLASH_CHIP_CAPACITY && addr < uploadedFile.size(); addr++) {
    uploadedFile.readBytes(buffer, 1);
    byte dat1 = buffer[0];
    byte dat2 = flashChip->readOneByte(addr);

    if (dat1 != dat2) {
      Serial.print("Verification failed at ");
      Serial.print(addr);
      Serial.print(" dat1: ");
      Serial.print(dat1);
      Serial.print(" dat2: ");
      Serial.println(dat2);
      status = "Failed to verify data";
      break;
    }
  }

  Serial.println("Done verifying");
  status = "Completed successfully";

  //vTaskDelete(NULL);
}

void FlashServer::handleWriteImage(AsyncWebServerRequest *request) {
  if (fileReady) {
    Serial.println("Starting to write");
    request->send(200);

    FlashServer::writeImage(NULL);

    // xTaskCreate(FlashServer::writeImage, "Write image to flash chip", 2048,
    //             NULL, 1, NULL);
  } else {
    Serial.println("File is not ready");
    request->send(500, "File is not ready");
  }
}

void FlashServer::handleFileUpload(AsyncWebServerRequest *request,
                                   String filename, size_t index, uint8_t *data,
                                   size_t len, bool final) {
  if (index == 0) {
    Serial.println("File upload start");
    fileReady = false;
  }

  uploadedFile = LittleFS.open("/image.bin", "w");
  uploadedFile.seek(index, SeekSet);
  uploadedFile.write(data, len);
  uploadedFile.close();

  if (final) {
    Serial.println("File upload done!");
    fileReady = true;
  }
}

void FlashServer::handleStatus(AsyncWebServerRequest *request) {
  request->send(200, "text/plain", status);
}
