"""Virtual Brother embroidery-card writer.

CardIO.dll (the C++ shim) forwards each of the nine CCardIO entry points here.
Instead of talking to a USB card writer over the wire, we pretend a writer and a
blank card are present, let PED-Basic hand us the patterns, and save the card
image PED-Basic wanted to burn.

Every argument arrives as a plain integer holding a 32-bit address in
pelite.exe's own address space -- we are running inside that process, so ctypes
can read and write it directly.

Values here come from reversing PED-Basic 1.07 / CardIO.dll 3.2.1.1; see
NOTES.md for where each one was found.
"""

import ctypes
import json
import os
import random
import struct
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------
# CIOError. pelite.exe compares against 0x18 and treats everything else as a
# failure to report, so 0x18 is the only value that lets a write proceed.
# --------------------------------------------------------------------------

IO_OK = 0x18
IO_NOT_CONNECTED = 0x01
IO_NO_CARD = 0x03
IO_WRONG_CARD = 0x04
IO_CARD_BUSY = 0x05
IO_TOO_LARGE = 0x06
IO_NO_MEMORY = 0x0B
IO_BAD_VOLUME = 0x17

# Card geometry, keyed by the size code the real DLL reads back from hardware.
CARD_SIZES = {1: 0x80000, 2: 0x100000, 3: 0x200000}  # 512 KiB, 1 MiB, 2 MiB

# The real Send() writes a single 'b' byte at one of these offsets as its last
# step, chosen by hoop-size index. It completes the word "brother" in the header
# -- which is why a naive memory dump shows "\xffroth" and needs repairing.
BROTH_OFFSETS = {0: 0x100, 1: 0x170, 2: 0xC0, 3: 0x28E, 4: 0x280}

# Three random bytes written at this offset as a per-card serial.
CARD_ID_OFFSET = 0x18E
CARD_ID_LENGTH = 3

# Offsets into the original DLL's image (preferred base 0x10000000) of the two
# functions that turn a CObArray of patterns into a finished card image. We call
# them rather than reimplementing the serializer.
RVA_MEASURE = 0x6752  # void __thiscall (this, CObArray*, int* out_hoop_index)
RVA_BUILD = 0x6AC8    # void __thiscall (this, CObArray*, size, int* out_len, hoop)

# Scratch object the real Send() builds on its stack before serialising.
CTX_SIZE = 256        # the original uses 108 bytes; over-allocate and zero it
CTX_BUFFER = 0x00     # void*  card image buffer
CTX_SIZE_CODE = 0x1C  # int    1/2/3, normally read back from the card
CTX_CARD_TYPE = 0x28  # int    the CCardIO constructor argument


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def _load_config():
    cfg = {
        "output": os.path.join(HERE, "image.bin"),
        "card_size_code": 1,      # 1 = 512 KiB, matches the ESP32 flash chip
        "original_dll": os.path.join(HERE, "CardIO_orig.dll"),
        "firmware_version": [3, 2, 1, 1],
        "capture": True,          # also save the raw pattern list for debugging
    }
    path = os.path.join(HERE, "cardio_config.json")
    if os.path.exists(path):
        try:
            with open(path) as fh:
                cfg.update(json.load(fh))
        except Exception:
            log("config: failed to read %s\n%s" % (path, traceback.format_exc()))
    for key, env in (("output", "CARDIO_OUTPUT"),
                     ("original_dll", "CARDIO_ORIGINAL_DLL")):
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    if os.environ.get("CARDIO_CARD_SIZE_CODE"):
        cfg["card_size_code"] = int(os.environ["CARDIO_CARD_SIZE_CODE"])
    return cfg


def log(msg):
    try:
        with open(os.path.join(HERE, "cardio-py.log"), "a") as fh:
            fh.write("[py] %s\n" % msg)
    except Exception:
        pass


CFG = _load_config()


# --------------------------------------------------------------------------
# Calling __thiscall functions from Python.
#
# ctypes speaks cdecl and stdcall but not __thiscall (this in ECX, arguments on
# the stack, callee cleans up). We assemble a throwaway x86 stub per call that
# loads ECX, pushes the arguments and jumps to the target.
# --------------------------------------------------------------------------

_PAGE_EXECUTE_READWRITE = 0x40
_MEM_COMMIT_RESERVE = 0x3000
_MEM_RELEASE = 0x8000

_kernel32 = ctypes.windll.kernel32
_kernel32.VirtualAlloc.restype = ctypes.c_void_p
_kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_uint32, ctypes.c_uint32]
_kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]


def thiscall(target, this, *args):
    """Invoke a __thiscall function and return its EAX value."""
    code = b""
    for value in reversed(args):                      # push args right-to-left
        code += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)
    code += b"\xB9" + struct.pack("<I", this & 0xFFFFFFFF)      # mov ecx, this
    code += b"\xB8" + struct.pack("<I", target & 0xFFFFFFFF)    # mov eax, target
    code += b"\xFF\xD0"                                          # call eax
    code += b"\xC3"                                              # ret

    addr = _kernel32.VirtualAlloc(None, len(code), _MEM_COMMIT_RESERVE,
                                  _PAGE_EXECUTE_READWRITE)
    if not addr:
        raise OSError("VirtualAlloc failed for thiscall stub")
    try:
        ctypes.memmove(addr, code, len(code))
        stub = ctypes.CFUNCTYPE(ctypes.c_int)(addr)
        return stub()
    finally:
        _kernel32.VirtualFree(ctypes.c_void_p(addr), 0, _MEM_RELEASE)


# --------------------------------------------------------------------------
# MFC CObArray, as laid out by MFC42.
# --------------------------------------------------------------------------

class CObArray(ctypes.Structure):
    _fields_ = [
        ("vfptr", ctypes.c_uint32),
        ("m_pData", ctypes.c_uint32),     # CObject**
        ("m_nSize", ctypes.c_int32),
        ("m_nMaxSize", ctypes.c_int32),
        ("m_nGrowBy", ctypes.c_int32),
    ]


def obarray_count(ptr):
    if not ptr:
        return 0
    return CObArray.from_address(ptr).m_nSize


# --------------------------------------------------------------------------
# The original DLL, used purely as an image serialiser.
#
# We do not let it touch the USB layer: we call only the two pure functions that
# turn patterns into bytes. Loading it also runs its DllMain, which is harmless.
# --------------------------------------------------------------------------

_original = None
_original_base = None


def _load_original():
    global _original, _original_base
    if _original_base is not None:
        return _original_base
    path = CFG["original_dll"]
    if not os.path.exists(path):
        log("original DLL not found at %s -- cannot serialise a card image. "
            "Rename the stock CardIO.dll to CardIO_orig.dll." % path)
        return None
    _original = ctypes.WinDLL(path)
    _original_base = _original._handle
    log("loaded serialiser %s at base 0x%08X" % (path, _original_base))
    return _original_base


def _build_image(obarray_ptr, card_type, size_code, hoop_override):
    """Produce the finished card image, or raise."""
    base = _load_original()
    if base is None:
        return None, None

    card_bytes = CARD_SIZES[size_code]

    # The scratch context the real Send() would have built on its stack.
    ctx = (ctypes.c_ubyte * CTX_SIZE)()
    ctypes.memset(ctx, 0, CTX_SIZE)
    ctx_addr = ctypes.addressof(ctx)

    image = (ctypes.c_ubyte * card_bytes)()
    ctypes.memset(image, 0xFF, card_bytes)   # erased flash reads as 0xFF

    struct.pack_into("<I", ctx, CTX_BUFFER, ctypes.addressof(image))
    struct.pack_into("<i", ctx, CTX_SIZE_CODE, size_code)
    struct.pack_into("<i", ctx, CTX_CARD_TYPE, card_type)

    # Which hoop the patterns need, unless PED-Basic already decided.
    hoop = ctypes.c_int(0)
    thiscall(base + RVA_MEASURE, ctx_addr, obarray_ptr, ctypes.addressof(hoop))
    hoop_index = hoop.value
    if hoop_override is not None:
        if hoop_override < hoop_index:
            log("requested hoop %d is smaller than required %d"
                % (hoop_override, hoop_index))
            return None, IO_BAD_VOLUME
        hoop_index = hoop_override

    used = ctypes.c_uint32(card_bytes)
    thiscall(base + RVA_BUILD, ctx_addr, obarray_ptr, card_bytes,
             ctypes.addressof(used), hoop_index)

    data = bytearray(image)

    # Two finishing touches the real Send() applies after the bulk transfer.
    for i in range(CARD_ID_LENGTH):
        data[CARD_ID_OFFSET + i] = random.randrange(256)
    if hoop_index in BROTH_OFFSETS:
        data[BROTH_OFFSETS[hoop_index]] = ord("b")
    else:
        log("unknown hoop index %d -- header 'b' byte not written" % hoop_index)

    log("built image: hoop=%d used=%d of %d bytes"
        % (hoop_index, used.value, card_bytes))
    return bytes(data), None


def _report_progress(fn_ptr, ctx_ptr, percent):
    """Drive PED-Basic's progress dialog so it doesn't sit at 0%."""
    if not fn_ptr:
        return
    try:
        cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_int)(fn_ptr)
        cb(ctypes.c_void_p(ctx_ptr), percent)
    except Exception:
        log("progress callback failed:\n%s" % traceback.format_exc())


# --------------------------------------------------------------------------
# Entry points called by CardIO.dll
# --------------------------------------------------------------------------

_instances = {}


def create(this, card_type):
    _instances[this] = {"card_type": card_type}
    log("CCardIO(%d)" % card_type)
    return 0


def destroy(this):
    _instances.pop(this, None)
    return 0


def reset_card_id(this):
    return 0


def write_executable_num(this, n):
    log("WriteExecutableNum(%d)" % n)
    return IO_OK


def chk_card_writer_connected(this, port, version_ptr, out_ptr):
    """Report a healthy card writer. pelite.exe passes NULL for both outputs."""
    try:
        if version_ptr:
            fw = bytes(CFG["firmware_version"])
            ctypes.memmove(version_ptr, fw, len(fw))
        if out_ptr:
            ctypes.c_int32.from_address(out_ptr).value = 1
        return IO_OK
    except Exception:
        log("chk_card_writer_connected failed:\n%s" % traceback.format_exc())
        return IO_NOT_CONNECTED


def chk_card_volume(this, obarray_ptr, total_ptr, used_ptr, atrb_ptr):
    """Report card capacity and how much of it the pending patterns need.

    PED-Basic calls this before Send() and refuses to continue unless it gets
    IO_OK back, so this is where an over-large design gets rejected.
    """
    try:
        size_code = CFG["card_size_code"]
        if size_code not in CARD_SIZES:
            log("bad card_size_code %r in config" % size_code)
            return IO_BAD_VOLUME
        card_bytes = CARD_SIZES[size_code]

        if total_ptr:
            ctypes.c_int32.from_address(total_ptr).value = card_bytes

        card_type = _instances.get(this, {}).get("card_type", 0)
        hoop_override = None
        if atrb_ptr:
            hoop_override = ctypes.c_int32.from_address(atrb_ptr).value

        image, err = _build_image(obarray_ptr, card_type, size_code, hoop_override)
        if err is not None:
            return err
        if image is None:
            return IO_NOT_CONNECTED

        # The real DLL reports the used length here; recompute it as the extent
        # of non-erased data so PED-Basic's "card full" logic still works.
        used = len(image.rstrip(b"\xFF"))
        if used_ptr:
            ctypes.c_int32.from_address(used_ptr).value = used
        log("ChkCardVolume: %d of %d bytes used" % (used, card_bytes))

        if used > card_bytes:
            return IO_TOO_LARGE
        return IO_OK
    except Exception:
        log("chk_card_volume failed:\n%s" % traceback.format_exc())
        return IO_NOT_CONNECTED


def send(this, obarray_ptr, progress_fn, progress_ctx, atrb_ptr):
    """Write the card image to a file instead of to a USB card writer."""
    try:
        size_code = CFG["card_size_code"]
        if size_code not in CARD_SIZES:
            return IO_BAD_VOLUME

        card_type = _instances.get(this, {}).get("card_type", 0)
        hoop_override = None
        if atrb_ptr:
            hoop_override = ctypes.c_int32.from_address(atrb_ptr).value

        if CFG.get("capture"):
            _capture(obarray_ptr)

        image, err = _build_image(obarray_ptr, card_type, size_code, hoop_override)
        if err is not None:
            return err
        if image is None:
            return IO_NOT_CONNECTED

        # The real transfer reports progress in eight steps; mirror that so the
        # dialog animates and closes cleanly.
        for step in range(1, 9):
            _report_progress(progress_fn, progress_ctx, step * 100 // 8)

        out = CFG["output"]
        with open(out, "wb") as fh:
            fh.write(image)
        log("Send: wrote %d bytes to %s" % (len(image), out))
        return IO_OK
    except Exception:
        log("send failed:\n%s" % traceback.format_exc())
        return IO_NOT_CONNECTED


def receive(this, obarray_ptr, arg, progress_fn, progress_ctx):
    """Reading a card back is not supported; there is no card to read."""
    log("Receive() called -- not implemented")
    return IO_NO_CARD


def _capture(obarray_ptr):
    """Dump the raw pattern list so the serialiser can be studied offline."""
    try:
        count = obarray_count(obarray_ptr)
        path = os.path.join(HERE, "capture.bin")
        arr = CObArray.from_address(obarray_ptr)
        with open(path, "wb") as fh:
            fh.write(b"CARDIOCAP")
            fh.write(struct.pack("<II", count, arr.m_pData))
            for i in range(count):
                elem = ctypes.c_uint32.from_address(arr.m_pData + i * 4).value
                fh.write(struct.pack("<I", elem))
                if elem:
                    blob = (ctypes.c_ubyte * 0x100).from_address(elem)
                    fh.write(bytes(blob))
        log("captured %d pattern(s) to %s" % (count, path))
    except Exception:
        log("capture failed:\n%s" % traceback.format_exc())
