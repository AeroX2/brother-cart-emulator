Place radare2 and cracker.py in the same directory as PED-Basic

Run `python cracker.py` in cmd from the PED-Basic directory. 
Once the program opens, add the PES file, hit the arrow to move it to the chip side of the screen and then hit the write to card button,
this should dump a image.bin which can be used in a custom flash chip.

Make sure `cracker.py` has write permission for pelite.exe