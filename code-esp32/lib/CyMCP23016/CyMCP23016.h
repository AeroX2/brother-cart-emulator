/**
 * CyMCP23016.h
 * Version 1.0.1
 * Author:
 *  Chris (Cyrus) Brunner
 * 
 * This library provides an interface to the Microchip MCP23016 I/O expander over I2C.
 */

#ifndef CyMCP23016_h
#define CyMCP23016_h

#include <Arduino.h>
#include <Wire.h>

#define MCP23016_ADDRESS 0x20 // Default I2C address

// Registers
#define MCP23016_GPIO0 0x00   // Data port register 0
#define MCP23016_GPIO1 0x01   // Data port register 1
#define MCP23016_OLAT0 0x02   // Access output latch register 0
#define MCP23016_OLAT1 0x03   // Access output latch register 1
#define MCP23016_IPOL0 0x04   // Access input polarity port register 0
#define MCP23016_IPOL1 0x05   // Access input polarity port register 1
#define MCP23016_IODIR0 0x06  // I/O direction register 0
#define MCP23016_IODIR1 0x07  // I/O direction register 1
#define MCP23016_INTCAP0 0x08 // Interrupt capture 0
#define MCP23016_INTCAP1 0x09 // Interrupt capture 1
#define MCP23016_IOCON0 0x0A  // I/O Expander control register 0
#define MCP23016_IOCON1 0x0B  // I/O Expander control register 1

// Pins
#define MCP23016_PIN_GPIO0_0 0  // Port 0, Pin 0
#define MCP23016_PIN_GPIO0_1 1  // Port 0, Pin 1
#define MCP23016_PIN_GPIO0_2 2  // Port 0, Pin 2
#define MCP23016_PIN_GPIO0_3 3  // Port 0, Pin 3
#define MCP23016_PIN_GPIO0_4 4  // Port 0, Pin 4
#define MCP23016_PIN_GPIO0_5 5  // Port 0, Pin 5
#define MCP23016_PIN_GPIO0_6 6  // Port 0, Pin 6
#define MCP23016_PIN_GPIO0_7 7  // Port 0, Pin 7
#define MCP23016_PIN_GPIO1_0 8  // Port 1, Pin 0
#define MCP23016_PIN_GPIO1_1 9  // Port 1, Pin 1
#define MCP23016_PIN_GPIO1_2 10 // Port 1, Pin 2 
#define MCP23016_PIN_GPIO1_3 11 // Port 1, Pin 3
#define MCP23016_PIN_GPIO1_4 12 // Port 1, Pin 4
#define MCP23016_PIN_GPIO1_5 13 // Port 1, Pin 5
#define MCP23016_PIN_GPIO1_6 14 // Port 1, Pin 6
#define MCP23016_PIN_GPIO1_7 15 // Port 1, Pin 7

/**
 * A Hardware abstraction class for the Microchip MCP23016 I/O expander.
 */
class CyMCP23016 {
public:
    /**
    * Default ctor.
    */
    CyMCP23016();

    /**
     * Initializes the MCP23016 given its hardware selected address.
     * See datasheet for address selection. This method should be
     * used on Arduino boards with dedicated SDA/SCL pins.
     * @param address The address to initialize at.
     */
    void begin(uint8_t address);

    /**
     * Initializes the MCP23016 at its default address. This method
     * should be used on Arduino boards with dedicated SDA/SCL pins.
     */
    void begin();

    /**
     * Sets the mode for the specified pin (INPUT or OUTPUT).
     * @param pin The pin 
     * @param direction
     */
    void pinMode(uint8_t pin, uint8_t direction);

    /**
     * Reads the values of all pins on both all in one pass.
     * @returns A 16-bit unsigned integer containing the bit value
     * of each pin in order.
     */
    uint16_t readAllPins();

    /**
     * Reads the values of all pins for the specified port in one pass.
     * @param port The port to read from (MCP23016_GPIO0 or MCP23016_GPIO1).
     * @returns An 8-bit unsigned integer containing the bit value of
     * each pin in order.
     */
    uint8_t readAllPinsForPort(uint8_t port);

    /**
     * Writes the specified 16-bit value across all pins on both ports in order.
     * @param value The 16-bit value containing each bit to write to each pin
     * on both ports.
     */
    void writeAllPins(uint16_t value);

    /**
     * Writes the specified value to the specified pin.
     * @param pin The pin to write the value for.
     * @param value The value to write (HIGH or LOW).
     */
    void digitalWrite(uint8_t pin, uint8_t value);

    /**
     * Reads the value from the specified pin.
     * @param pin The pin to read from.
     * @returns The pin value (HIGH or LOW).
     */
    uint8_t digitalRead(uint8_t pin);

    /**
     * Attempts to detect the I2C device at the default or specified address.
     * @returns true if the device was detected; Otherwise, false.
     */
    bool detected();

    void debug();
private:
    /**
     * Gets the bit number associated with a given pin.
     * @param pin The pin to get the bit number for.
     * @returns The bit number associated with the specified pin.
     */
    uint8_t bitForPin(uint8_t pin);

    /**
     * Gets the register address (port dependent) for a given pin.
     * @param pin The pin to get the register address for.
     * @param portA_addr The address of port A.
     * @param portB_addr The address of port B.
     * @returns The register address for the specified pin.
     */
    uint8_t regForPin(uint8_t pin, uint8_t portA_addr, uint8_t portB_addr);

    /**
     * Reads the byte value from the specified register address.
     * @param addr The register address to read from.
     * @returns The value returned from the specified register.
     */
    uint8_t readRegister(uint8_t addr);

    /**
     * Writes the specified value to the specified register address.
     * @param addr The register address.
     * @param value The byte value to write.
     */
    void writeRegister(uint8_t addr, uint8_t value);

    /**
     * Helper method to update a single bit of a port 0/1 register.
     * This will read the current register value, then write the new value.
     * @param pin The pin to update the register value for.
     * @param value The new value to write.
     * @param portA_addr Port A(0) address.
     * @param portB_addr Port B(1) address.
     */
    void updateRegisterBit(uint8_t pin, uint8_t value, uint8_t portA_addr, uint8_t portB_addr);

    uint8_t _i2cAddr;
};

#endif