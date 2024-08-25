import os
import re
import struct

app_path = os.path.join(os.getcwd(), 'radare2', 'bin')
os.environ["PATH"] += os.pathsep + app_path

# the patches dictionary contains x86 opcodes to be replaced at pre-known locations;
# this is where the magic happens
patches = {
    # 0x90: Mnemonic "NOP" ("No Operation")
    # 0xEB: Mnemonic "JMP rel8" ("Short Relative Jump")
    0x4136EA: 0x90,
    0x4136EB: 0x90,
    0x4136EC: 0x90,
    0x4136ED: 0x90,
    0x4136EE: 0x90,
    0x4136EF: 0x90,
    
    0x41C7C1: 0x90,
    0x41C7C2: 0x90,
    
    0x413DF1: 0xEB,
    
    0x10005DD8: 0xEB,
    0x10005E20: 0xEB,
    0x10005E6B: 0xEB,
}

import r2pipe
# load the PED Basic Windows executable with r2
print("Loading executable...")
r = r2pipe.open('pelite.exe', ['-w'])

# run multiple r2 commands (returns the output of the command executions)
# "ood": reopen in debug mode
# "dc": continue execution of all children
print("Reopening in debug mode and continuing execution...")
print(r.cmd("ood; dc; dc;"))

# list symbols of target lib ("dmi")
relocs = r.cmd("dmij")
print("Printing target library symbols...")
print(relocs)
relocs = relocs.split("\n")
cardios = [line for line in relocs if "CardIO.dll" in line]
cardio_addr = int(re.findall(r"0x([0-9A-Fa-f]+)", cardios[-1])[0],16)

print("Applying patches...")
for patch_addr, patch_val in patches.items():
    if patch_addr > 0x10000000:
        patch_addr -= 0x10000000
        patch_addr += cardio_addr

    # apply patches by writing known values at known addresses ("w [str] [@addr]")
    cmd = "w \\x{:x} @ {}".format(patch_val, patch_addr)
    print(cmd)
    r.cmd(cmd)

offset = cardio_addr + 0x6ad2
# continue until address ("dcu")
print("Continuing. GUI should open...")
print("Output here will continue after card download attempt. Have fun!")
r.cmd("dcu {}".format(offset))

# r2pipe has some weird buffering issue with json commands and 
# doesn't seem to work the first time
mem = None
for i in range(5):
    mem = r.cmdj("p8j 4 @ rcx")
    if mem is not None and len(mem) > 0:
        break
 

# we get here after performing a write operation to the card
print("Sending to virtual embroidery card. Printing memory...")
print(mem)
mem = struct.pack("4B", *mem)
print(mem)
mem = int.from_bytes(mem, "little")
print(mem)

offset = cardio_addr + 0x6b0e
# continue until that address
r.cmd("dcu {}".format(offset))

# Ditto
data = None
for i in range(5):
    data = bytes(r.cmdj("pxj 0x10000 @ {}".format(mem)))
    if data is not None and len(data) > 0:
        break

# got all the binary data
print("Got {} bytes of card data.".format(len(data)))

# perform a sanity check: look for expected data in the whole blob
magic_string_expected = b'created by PED-Basic'
magic_string_read = data[50:70]
if magic_string_read == magic_string_expected:
    # looks good, so let's finally store it as a binary file
    print("Writing output to binary file...")
    f = open("image.bin", "wb")
    f.write(data)
    f.close()
    print("Done.")
else:
    print("Expected '{}' but got '{}'.".format(magic_string_expected.decode("ascii"),
                                               magic_string_read.decode("ascii")))
