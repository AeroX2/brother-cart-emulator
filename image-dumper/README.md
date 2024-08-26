Place radare2 and cracker.py in the same directory as PED-Basic

Run `python cracker.py` in cmd from the PED-Basic directory. 
Once the program opens, add the PES file, hit the arrow to move it to the chip side of the screen and then hit the write to card button,
this should dump a image.bin which can be used in a custom flash chip.

Make sure `cracker.py` has write permission for pelite.exe


## Technical information about the patches

`ChkCardVolume` seems to contact the EEPROM and check that the data is formatted correctly and not corrupted.

0x4136EA - 0x4136EF -> Bypass ChkCardVolume (pelite.exe) ![Reverse 1](./images/reverse1.png?raw=true "Reverse 1")

0x41C7C1 - 0x41C7C2 -> Bypass ChkCardVolume (pelite.exe) ![Reverse 2](./images/reverse2.png?raw=true "Reverse 2")

0x413DF1 -> Bypass ChkCardVolume (pelite.exe) ![Reverse 3](./images/reverse3.png?raw=true "Reverse 3")

0x10005DD8 -> Bypass check that EEPROM exists (CardIO.dll) ![Reverse 4](./images/reverse4.png?raw=true "Reverse 4")

0x10005E20 -> Bypass check that calls ChkCardVolume (CardIO.dll) ![Reverse 5](./images/reverse5.png?raw=true "Reverse 5")

0x10005E6B -> Force the card size to 0x80000 bytes (CardIO.dll) ![Reverse 6](./images/reverse6.png?raw=true "Reverse 6")


## Tested configurations

* AeroX2: Windows 11 + PED-Basic 1.07 (CardIO.dll 3.2.1.1) + Python 3.12.0 + r2pipe 1.9.4 + radare2-5.9.4-w64
* maehw: Windows 10 + PED-Basic 1.07 (CardIO.dll 3.2.1.1) + Python 3.12.5 + r2pipe 1.9.4 + radare2-5.8.2-w64 / radare2-5.9.4-w64
