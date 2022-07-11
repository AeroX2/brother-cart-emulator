#ifndef FLASHSERVER_H
#define FLASHSERVER_H

#include <Arduino.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <LittleFS.h>
#include <WiFi.h>

#include "flashchip.h"
#include "webpage.h"

class FlashServer {
 private:
  AsyncWebServer webServer;

  static FlashChip* flashChip;
  static File uploadedFile;
  static const char* status;
  static bool fileReady;

  static void handleRoot(AsyncWebServerRequest* request);

  static void writeImage(void* parameter);
  static void handleWriteImage(AsyncWebServerRequest* request);

  static void handleFileUpload(AsyncWebServerRequest* request, String filename,
                               size_t index, uint8_t* data, size_t len,
                               bool final);
  static void handleStatus(AsyncWebServerRequest* request);
 public:
  FlashServer() : webServer(80) {}

  void init(FlashChip* _flashChip);
};

#endif
