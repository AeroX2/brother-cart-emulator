# CyMCP23016

[![Build Status](https://travis-ci.com/cyrusbuilt/CyMCP23016.svg?branch=master)](https://travis-ci.com/cyrusbuilt/CyMCP23016)

An Arduino library for the Microchip MCP2016 I/O Expander IC. Based on the Adafruit library for the MCP23017.  I created this library because I didn't find an Arduino library for the MCP23016 that I liked. The [Adafruit MCP23017 library](https://github.com/adafruit/Adafruit-MCP23017-Arduino-Library) would have been ideal, but is only compatible with the MCP23017. This library derived from the Adafruit library to provide the same simplicity and ease of use, but for the MCP23016. This library is compatible with both ATmel AVR and Espressif ESP boards. The Microchip MCP23016 is a 16-bit I/O expander. It provides 16 additional GPIO pins accessible via I2C. See the [MCP23016 datasheet](http://ww1.microchip.com/downloads/en/devicedoc/20090c.pdf). Unlike the MCP23017, the MCP23016 does not have builtin pullup resisters. While interrupts are supported on the MCP23016, they have not been implemented in this library yet.

## How to use

Include CyMCP23016.h in your sketch, connect the MCP23016's SDA and SCL pins to your Arduino's SDA and SCL pins and then you can configure and read/write pins similar to a regular Arduino pin as shown in the example below:

```cpp
#include <Arduino.h>
#include "CyMCP23016.h"

#define LED_PIN MCP23016_PIN_GPIO0_0  // Attach LED to Port 0, Pin 0

CyMCP23016 mcp;

void setup() {
    Serial.begin(9600);

    // Init the MCP23016 at the default address.
    mcp.begin();

    // Init the LED pin.
    mcp.pinMode(LED_PIN, OUTPUT);
    mcp.digitalWrite(LED_PIN, LOW);
}

void loop() {
    delay(1000);

    // Turn the LED on, then read back the state to verify.
    mcp.digitalWrite(LED_PIN, HIGH);
    uint8_t state = mcp.digitalRead(LED_PIN);
    Serial.print(F("LED is ));
    Serial.println(state == HIGH ? "ON", "OFF");

    delay(1000);

    // Turn the LED off, then
    mcp.digitalWrite(LED_PIN, LOW);
    state == mcp.digitalRead(LED_PIN);
    Serial.print(F("LED is ));
    Serial.println(state == HIGH ? "ON" : "OFF");
}
```

## How to install

For PlatformIO:

```bash
platformio lib install CyMCP23016
```

For Arudino IDE: See [https://www.arduino.cc/en/Guide/Libraries](https://www.arduino.cc/en/Guide/Libraries)
