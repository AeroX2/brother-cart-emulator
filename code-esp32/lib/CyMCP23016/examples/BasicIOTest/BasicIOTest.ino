/**
 * Basic input/output test for MCP23016 expander.
 */

#include <Arduino.h>
#include "CyMCP23016.h"

#ifdef ESP8266
#define PIN_SDA 4
#define PIN_SCL 5
#endif

CyMCP23016 mcp;

void setup() {
    Serial.begin(115200);

#ifdef __AVR
    // Init MCP23016 at the default address. This assumes we are running on
    // an ATmel AVR-based arduino, like the Arduino Uno.
    mcp.begin();
#elif defined(ESP8266)
    // Init MCP23016 at the default address. This assumes we are running
    // on an Adafruit Huzzah ESP8266, which shares SDA and SCL with
    // GPIOs 4 & 5, respectively.
    mcp.begin(PIN_SDA, PIN_SCL);
#endif

    // Set Pin 0 on Port 0 as an output.
    mcp.pinMode(MCP23016_PIN_GPIO0_0, OUTPUT);
}

void loop() {
    delay(1000);

    // Set the pin HIGH and read back the state.
    mcp.digitalWrite(MCP23016_PIN_GPIO0_0, HIGH);
    uint8_t val = mcp.digitalRead(MCP23016_PIN_GPIO0_0);
    Serial.print(F("Pin 0.0 is "));
    Serial.println(val == HIGH ? "HIGH" : "LOW");

    delay(1000);

    // Set the pin LOW and read back the state.
    mcp.digitalWrite(MCP23016_PIN_GPIO0_0, LOW);
    val = mcp.digitalRead(MCP23016_PIN_GPIO0_0);
    Serial.print(F("Pin 0.0 is "));
    Serial.println(val == HIGH ? "HIGH" : "LOW");
}