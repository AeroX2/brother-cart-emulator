/**
 * CyMCP23016.cpp
 * Version 1.0.1
 * Author:
 *  Chris (Cyrus) Brunner
 * 
 * This library provides an interface to the Microchip MCP23016 I/O expander over I2C.
 */

#include <pgmspace.h>
#include "CyMCP23016.h"

CyMCP23016::CyMCP23016() {

}

uint8_t CyMCP23016::bitForPin(uint8_t pin) {
    return pin % 8;
}

uint8_t CyMCP23016::regForPin(uint8_t pin, uint8_t portA_addr, uint8_t portB_addr) {
    return (pin < 8) ? portA_addr : portB_addr;
}

uint8_t CyMCP23016::readRegister(uint8_t addr) {
    Wire.beginTransmission(MCP23016_ADDRESS | this->_i2cAddr);
    Wire.write(addr);
    Wire.endTransmission();
    Wire.requestFrom(MCP23016_ADDRESS | this->_i2cAddr, 1);
    return Wire.read();
}

void CyMCP23016::writeRegister(uint8_t addr, uint8_t value) {
    Wire.beginTransmission(MCP23016_ADDRESS | this->_i2cAddr);
    Wire.write(addr);
    Wire.write(value);
    Wire.endTransmission();
}

void CyMCP23016::updateRegisterBit(uint8_t pin, uint8_t value, uint8_t portA_addr, uint8_t portB_addr) {
    uint8_t regAddr = this->regForPin(pin, portA_addr, portB_addr);
    uint8_t bit = this->bitForPin(pin);
    uint8_t regValue = this->readRegister(regAddr);
    bitWrite(regValue, bit, value);
    this->writeRegister(regAddr, regValue);
}

void CyMCP23016::begin(uint8_t addr) {
    if (addr > 7) {
        addr = 7;
    }

    this->_i2cAddr = addr;
    Wire.begin();
	Wire.setClock(100000/2);
	
    this->writeRegister(MCP23016_IODIR0, 0xFF);
    this->writeRegister(MCP23016_IODIR1, 0xFF);
}

void CyMCP23016::begin() {
    this->begin(0);
}

void CyMCP23016::pinMode(uint8_t pin, uint8_t direction) {
    this->updateRegisterBit(pin, (direction == INPUT), MCP23016_IODIR0, MCP23016_IODIR1);
}

uint16_t CyMCP23016::readAllPins() {
    uint16_t bothPorts = 0;
    uint8_t port0;

    Wire.beginTransmission(MCP23016_ADDRESS | this->_i2cAddr);
    Wire.write(MCP23016_GPIO0);
    Wire.endTransmission();
    Wire.requestFrom(MCP23016_ADDRESS | this->_i2cAddr, 2);
    port0 = Wire.read();
    bothPorts = Wire.read();
    bothPorts <<= 8;
    bothPorts |= port0;
    return bothPorts;
}

uint8_t CyMCP23016::readAllPinsForPort(uint8_t port) {
    Wire.beginTransmission(MCP23016_ADDRESS | this->_i2cAddr);
    Wire.write(port == MCP23016_GPIO0 ? MCP23016_GPIO0 : MCP23016_GPIO1);
    Wire.endTransmission();
    Wire.requestFrom(MCP23016_ADDRESS | this->_i2cAddr, 1);
    return Wire.read();
}

void CyMCP23016::writeAllPins(uint16_t value) {
    Wire.beginTransmission(MCP23016_ADDRESS | this->_i2cAddr);
    Wire.write(MCP23016_GPIO0);
    Wire.write(value & 0xFF);
    Wire.write(value >> 8);
    Wire.endTransmission();
}

void CyMCP23016::digitalWrite(uint8_t pin, uint8_t value) {
    uint8_t bit = this->bitForPin(pin);
    uint8_t regAddr = this->regForPin(pin, MCP23016_OLAT0, MCP23016_OLAT1);
    uint8_t gpio = this->readRegister(regAddr);
    bitWrite(gpio, bit, value);
    regAddr = this->regForPin(pin, MCP23016_GPIO0, MCP23016_GPIO1);
    this->writeRegister(regAddr, gpio);
}

uint8_t CyMCP23016::digitalRead(uint8_t pin) {
    uint8_t bit = this->bitForPin(pin);
    uint8_t regAddr = this->regForPin(pin, MCP23016_GPIO0, MCP23016_GPIO1);
    return (this->readRegister(regAddr) >> bit) & 0x1;
}

bool CyMCP23016::detected() {
    Wire.beginTransmission(MCP23016_ADDRESS | this->_i2cAddr);
    return (Wire.endTransmission() == 0);
}