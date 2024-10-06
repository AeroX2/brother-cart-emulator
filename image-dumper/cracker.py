import os
import re
import struct
import argparse
import r2pipe
from sys import exit, stderr
from math import log2


tool_description = "Embroidery Card Image Dumping Tool"
card_sizes_kb = [512, 1024, 2048]  # the set of supported embroidery memory card sizes (in kiBytes)

def parse_args():
    parser = argparse.ArgumentParser(description=tool_description)

    # memory card size argument
    default_card_size = min(card_sizes_kb)
    parser.add_argument(
        "-cs", "--card-size",
        type=int,
        choices=card_sizes_kb,
        default=default_card_size,
        help="Size of the memory card in kiBytes (valid choices: {}). Default is {} kiBytes.".format(
            ','.join(([str(x) for x in card_sizes_kb])), default_card_size)
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

dll_offset = 0x10000000

# the patches dictionary contains x86 opcodes to be replaced at pre-known locations;
# this is where the magic happens
patches = {
    # 0x90: Mnemonic "NOP" ("No Operation")
    # 0xEB: Mnemonic "JMP rel8" ("Short Relative Jump")

    # ignore result values other than 0x18 from function at 0x0041343d which itself calls CCardIO::ChkCardVolume()
    0x4136EA: 0x90,
    0x4136EB: 0x90,
    0x4136EC: 0x90,
    0x4136ED: 0x90,
    0x4136EE: 0x90,
    0x4136EF: 0x90,

    # ignore result values other than 0x18 from function at 0x0041343d which itself calls CCardIO::ChkCardVolume()
    0x41C7C1: 0x90,
    0x41C7C2: 0x90,

    # ignore result values other than 0x18 from call to CCardIO::ChkCardVolume()
    0x413DF1: 0xEB,

    dll_offset + 0x5DD8: 0xEB,  # ignore result of card reader/writer firmware version check
    dll_offset + 0x5E20: 0xEB,  # ignore result of card reader/writer flash ID and memory content checks
}

# patches dependent on card size
card_size_patches = [
    # 512 kiBytes
    {
        dll_offset + 0x5E6B: 0xEB,  # mock card size of 512 kiBytes
    },
    # 1024 kiBytes
    {
        dll_offset + 0x5E6B: 0x90,  # mock card size of 1024 kiBytes
        dll_offset + 0x5E6C: 0x90,
        dll_offset + 0x5E6D: 0x90,
        dll_offset + 0x5E6E: 0x90,
        dll_offset + 0x5E6F: 0x90,
        dll_offset + 0x5E70: 0x90,
        dll_offset + 0x5E71: 0x90,
        dll_offset + 0x5E72: 0x90,
        dll_offset + 0x5E73: 0x90,
        dll_offset + 0x5E74: 0xEB,
    },
    # 2048 kiBytes
    {
        dll_offset + 0x5E6B: 0x90,  # mock card size of 2048 kiBytes
        dll_offset + 0x5E6C: 0x90,
        dll_offset + 0x5E6D: 0x90,
        dll_offset + 0x5E6E: 0x90,
        dll_offset + 0x5E6F: 0x90,
        dll_offset + 0x5E70: 0x90,
        dll_offset + 0x5E71: 0x90,
        dll_offset + 0x5E72: 0x90,
        dll_offset + 0x5E73: 0x90,
        dll_offset + 0x5E74: 0x90,
        dll_offset + 0x5E75: 0x90,
        dll_offset + 0x5E76: 0x90,
        dll_offset + 0x5E77: 0x90,
        dll_offset + 0x5E78: 0x90,
        dll_offset + 0x5E79: 0x90,
        dll_offset + 0x5E7A: 0x90,
        dll_offset + 0x5E7B: 0x90,
        dll_offset + 0x5E7C: 0x90,
        dll_offset + 0x5E7D: 0xEB,
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
        print("32 bit word: 0x{:x}".format(f))

print("Applying patches...")
for patch_addr, patch_val in patches.items():
    if patch_addr > dll_offset:
        patch_addr -= dll_offset
        patch_addr += cardio_addr

    # apply patches by writing known values at known addresses ("w [str] [@addr]")
    cmd = "w \\x{:x} @ 0x{:x}".format(patch_val, patch_addr)
    print(cmd)
    r.cmd(cmd)

print("Continuing. GUI should open...")
print("Output here will continue after card download attempt. Have fun!")

# we get here while performing a send/write operation to the card;
# extract the *address of the local memory buffer* where the card data is written to
# from register RCX (Microsoft x64 calling convention?); this allows us to extract the buffer later;
# technically continue execution until address ("dcu")
offset = cardio_addr + 0x6ad2
r.cmd("dcu {}".format(offset))
print("Preparing embroidery card memory...")

# r2pipe has some weird buffering issue with json commands and 
# doesn't seem to work the first time
mem = None
for i in range(5):
    mem = r.cmdj("p8j 4 @ rcx")
    if mem is not None and len(mem) > 0:
        break

mem = struct.pack("4B", *mem)
mem = int.from_bytes(mem, "little")
print("Memory is at: 0x{:x}".format(mem))
if mem == 0xFFFFFFFF:
    print("Invalid memory address PED-Basic may have been terminated w/o writing to the card.", file=stderr)
    exit(1)

# continue execution until we hit hte address where we can extract the locally buffer card memory with all valid data;
# all data has been written here before it would finally be transferred to the card via USB
offset = cardio_addr + 0x6b0e
r.cmd("dcu {}".format(offset))
print("Embroidery card memory ready for extraction...")

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

# make broth where we see the ingredients for it (fixes an incomplete/corrupt file header);
# meaning: search for b'\xffroth' at known locations and replace them with b'broth' (write the final 'b' character)
broth_locations_candidates = [0xC0, 0x100, 0x170]  # memory location depends on the selected hoop size
for l in broth_locations_candidates:
    if data[l : l+5] == b'\xffroth':
        data = data[0:l] + b'b' + data[l+1:]

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
