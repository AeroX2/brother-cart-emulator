import os
import re
import struct
import argparse
import r2pipe
from sys import exit, stderr
from math import log2


tool_description = "Embroidery Card Image Dumping Tool"
card_sizes_kb = [64, 128, 256]  # the set of supported embroidery memory card sizes (in kiBytes)

def parse_args():
    parser = argparse.ArgumentParser(description=tool_description)

    # memory card size argument
    parser.add_argument(
        "-cs", "--card-size",
        type=int,
        choices=card_sizes_kb,
        default=64,
        help="Size of the memory card in kiBytes (valid options: 64, 128, 256). Default is 64 kiBytes."
    )

    # radare2 binary path argument
    parser.add_argument(
        "-r2b", "--radare2-binpath",
        type=str,
        default=os.path.join(os.getcwd(), 'radare2', 'bin'),
        help="Path to the radare2 binary (folder, not the binary itself). Default is './radare2/bin' relative to the current working directory."
    )

    # PED-Basic binary path argument
    parser.add_argument(
        "-pedb", "--pedbasic-binpath",
        type=str,
        default=os.getcwd(),
        help="Path to the PED-Basic binary (folder, not the 'pelite.exe' binary itself). Default is the current working directory."
    )

    # Output file argument
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="image.bin",
        help="Path to the output file. Default is 'image.bin'."
    )

    args = parser.parse_args()
    return args


# parse and dump the command line arguments
cli_args = parse_args()
print("Selected card size: {} kiBytes".format(cli_args.card_size))
print("Search path for r2 binary: '{}'".format(cli_args.radare2_binpath))
print("Search path for PED-Basic binary: '{}'".format(cli_args.pedbasic_binpath))
print("Path of binary image output file: '{}'".format(cli_args.output))

os.environ["PATH"] += os.pathsep + cli_args.radare2_binpath

ped_exec = os.path.join(cli_args.pedbasic_binpath, 'pelite.exe')

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
}

# patches dependent on card size
card_size_patches = [
    # 64 kiBytes
    {
        0x10005E6B: 0xEB,
    },
    # 128 kiBytes
    {
        0x10005E6B: 0x90,
        0x10005E6C: 0x90,
        0x10005E6D: 0x90,
        0x10005E6E: 0x90,
        0x10005E6F: 0x90,
        0x10005E70: 0x90,
        0x10005E71: 0x90,
        0x10005E72: 0x90,
        0x10005E73: 0x90,
        0x10005E74: 0xEB,
    },
    # 256 kiBytes
    {
        0x10005E6B: 0x90,
        0x10005E6C: 0x90,
        0x10005E6D: 0x90,
        0x10005E6E: 0x90,
        0x10005E6F: 0x90,
        0x10005E70: 0x90,
        0x10005E71: 0x90,
        0x10005E72: 0x90,
        0x10005E73: 0x90,
        0x10005E74: 0x90,
        0x10005E75: 0x90,
        0x10005E76: 0x90,
        0x10005E77: 0x90,
        0x10005E78: 0x90,
        0x10005E79: 0x90,
        0x10005E7A: 0x90,
        0x10005E7B: 0x90,
        0x10005E7C: 0x90,
        0x10005E7D: 0xEB,
    }
]

# append card-size dependent patches;
# use card size as index for array of dicts with,
# this works as long as we work with powers of 2 (i.e. 64/128/256 kiBytes)
card_size_patches = card_size_patches[int(log2(cli_args.card_size // min(card_sizes_kb)))]
patches.update(card_size_patches)

# load the PED Basic Windows executable with r2
print("Loading executable...")
r = r2pipe.open(ped_exec, ['-w'])

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
libname = "CardIO.dll"
cardios = [line for line in relocs if libname in line]
cardio_addr = int(re.findall(r"0x([0-9A-Fa-f]+)", cardios[-1])[0],16)

imports = r.cmd("ii")
imports = imports.split("\n")
print("Printing imported CardIO functions...")
for imp in imports:
    imp = imp.split()
    if len(imp) > 6 and imp[3] == 'FUNC' and imp[4] == libname:
        func_addr = imp[1]
        func_signature = "".join(imp[6:])
        print("signature: {}, address: {}".format(func_signature, func_addr))

        f = r.cmd("pxw 4 @ {}".format(func_addr))
        f = f.split()
        f = int(f[1], 16)
        #f += 0x10000000
        # f -= cardio_addr
        print("32 bit word: 0x{:x}".format(f))

print("Applying patches...")
for patch_addr, patch_val in patches.items():
    if patch_addr > 0x10000000:
        patch_addr -= 0x10000000
        patch_addr += cardio_addr

    # apply patches by writing known values at known addresses ("w [str] [@addr]")
    cmd = "w \\x{:x} @ 0x{:x}".format(patch_val, patch_addr)
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
print("Sending to virtual embroidery card...")
mem = struct.pack("4B", *mem)
mem = int.from_bytes(mem, "little")
print("Memory is at: 0x{:x}".format(mem))
if mem == 0xFFFFFFFF:
    print("Invalid memory address PED-Basic may have been terminated w/o writing to the card.", file=stderr)
    exit(1)

offset = cardio_addr + 0x6b0e
# continue until that address
r.cmd("dcu {}".format(offset))

# Ditto
card_size_bytes = cli_args.card_size*1024
data = None
for i in range(5):
    data = bytes(r.cmdj("pxj 0x{:x} @ {}".format(card_size_bytes, mem)))
    if data is not None and len(data) > 0:
        break

# got all the binary data
data_len_kb = len(data)/1024
print("Got {:.1f} kiBytes of card data.".format(data_len_kb))
if data_len_kb != cli_args.card_size:
    print("Expected {:.1f} kiBytes of card data.".format(cli_args.card_size), file=stderr)
    exit(1)

# check if the last few bytes are 0xFF (likely unused space);
# warn if they are not as we may have exceeded the card size limit w/o noticing earlier
num_last_bytes = 16
last_bytes = data[-num_last_bytes:]
print("Last {} bytes of memory: {}".format(num_last_bytes, last_bytes))
if b'\xFF'*num_last_bytes == last_bytes:
    print("Looks like empty/unused memory. That's as expected!")
else:
    print("[WARN] Last bytes in memory are non-empty. This can be an indicator for a card size memory overrun.", file=stderr)
    # check if we can recommend choosing a bigger sized card
    if any([cs > cli_args.card_size for cs in card_sizes_kb]):
        print("[WARN] Higher card sizes are available.", file=stderr)
    else:
        print("[WARN] No higher card sizes are available!", file=stderr)
    print("[WARN] Reduction of pattern files (.pes) and/or stitches per pattern or pattern size could(!) also help.", file=stderr)

# perform a sanity check: look for expected data in the whole blob
magic_string_expected = b'created by PED-Basic'
magic_string_len = len(magic_string_expected)
magic_string_read = data[50:50+magic_string_len]
if magic_string_read == magic_string_expected:
    # looks good, so let's finally store it as a binary file
    print("Writing output to binary file '{}'...".format(cli_args.output))
    f = open(cli_args.output, "wb")
    f.write(data)
    f.close()
    print("Done.")
else:
    print("Binary is lacking the magic string. Expected '{}' but got '{}'.".format(magic_string_expected.decode("ascii"),
                                               magic_string_read.decode("ascii")), file=stderr)
    exit(1)
