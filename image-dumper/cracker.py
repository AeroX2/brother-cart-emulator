import os
import re
import struct

app_path = os.path.join(os.getcwd(), 'radare2', 'bin')
os.environ["PATH"] += os.pathsep + app_path

patches = {
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
r = r2pipe.open('pelite.exe', ['-w'])

print(r.cmd("ood; dc; dc;"))

relocs = r.cmd("ir")
print(relocs)
relocs = relocs.split("\n")
cardios = [line for line in relocs if "CardIO.dll" in line]
cardio_addr = int(re.findall(r"0x([0-9A-F]+)", cardios[-1])[0],16)

for patch_addr, patch_val in patches.items():
    if (patch_addr > 0x10000000):
        patch_addr -= 0x10000000
        patch_addr += cardio_addr
    
    cmd = "w \\x{:x} @ {}".format(patch_val, patch_addr)
    print(cmd)
    r.cmd(cmd)

offset = cardio_addr + 0x6ad2
r.cmd("dcu {}".format(offset))

# r2pipe has some weird buffering issue with json commands and 
# doesn't seem to work the first time
mem = None
for i in range(5):
    mem = r.cmdj("p8j 4 @ rcx")
    if (mem != None and len(mem) > 0):
        break
 
    
print(mem)
mem = struct.pack("4B", *mem)
print(mem)
mem = int.from_bytes(mem, "little")
print(mem)

offset = cardio_addr + 0x6b0e
r.cmd("dcu {}".format(offset))

# Ditto
data = None
for i in range(5):
    data = bytes(r.cmdj("pxj 0x10000 @ {}".format(mem)))
    if (data != None and len(data) > 0):
        break

f = open("image.bin", "wb")
f.write(data)
f.close()
