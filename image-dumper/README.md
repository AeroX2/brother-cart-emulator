# README

## Usage

Place radare2 (the free reversing toolkit) and `cracker.py` (the Python script from this repository) in the same directory as PED-Basic.

Run `python cracker.py` in Windows command line (`cmd`) from the PED-Basic directory. 
Once PED-Basic opens, add the PES file, hit the arrow to move it to the chip side of the screen and then hit the write to card button,
this should dump a `image.bin` which can be used in a custom flash chip.

Make sure `cracker.py` has write permission for `pelite.exe`.

There are various command line options to change the default search paths (so that neither PED-Basic nor radare2 must be in the same directory) and the embroidery memory card size:

Run `python cracker.py --help` to list the options:

```
usage: cracker.py [-h] [-cs {512,1024,2048}] [-r2b RADARE2_BINPATH]
                  [-pedb PEDBASIC_BINPATH] [-o OUTPUT]

Embroidery Card Image Dumping Tool

options:
  -h, --help            show this help message and exit
  -cs {512,1024,2048}, --card-size {512,1024,2048}
                        Size of the memory card in kiBytes (valid choices:
                        512,1024,2048). Default is 512 kiBytes.
  -r2b RADARE2_BINPATH, --radare2-binpath RADARE2_BINPATH
                        Path to the radare2 binary (folder, not the binary
                        itself). Default is './radare2/bin' relative to the
                        current working directory.
  -pedb PEDBASIC_BINPATH, --pedbasic-binpath PEDBASIC_BINPATH
                        Path to the PED-Basic binary (folder, not the
                        'pelite.exe' binary itself). Default is the current
                        working directory.
  -o OUTPUT, --output OUTPUT
                        Path to the output file. Default is 'image.bin'.
```

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
