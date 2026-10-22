"""CPU temperature reader (IOKit). A separate program: small and fast to start, and if the reading hangs
the monitor is not affected."""
import ctypes
import sys


def temp_read():
    """CPU temperature (degrees C): average of the 'tdie' sensors read through IOKit HID (Apple Silicon, no password).
    Runs in a separate process: if the reading hangs, the main program is not affected."""
    iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    vp = ctypes.c_void_p
    cf.CFStringCreateWithCString.restype = vp
    cf.CFStringCreateWithCString.argtypes = [vp, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFNumberCreate.restype = vp
    cf.CFNumberCreate.argtypes = [vp, ctypes.c_int, vp]
    cf.CFDictionaryCreate.restype = vp
    cf.CFDictionaryCreate.argtypes = [vp, ctypes.POINTER(vp), ctypes.POINTER(vp), ctypes.c_long, vp, vp]
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFArrayGetCount.argtypes = [vp]
    cf.CFArrayGetValueAtIndex.restype = vp
    cf.CFArrayGetValueAtIndex.argtypes = [vp, ctypes.c_long]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = [vp, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
    iokit.IOHIDEventSystemClientCreate.restype = vp
    iokit.IOHIDEventSystemClientCreate.argtypes = [vp]
    iokit.IOHIDEventSystemClientSetMatching.restype = ctypes.c_int
    iokit.IOHIDEventSystemClientSetMatching.argtypes = [vp, vp]
    iokit.IOHIDEventSystemClientCopyServices.restype = vp
    iokit.IOHIDEventSystemClientCopyServices.argtypes = [vp]
    iokit.IOHIDServiceClientCopyProperty.restype = vp
    iokit.IOHIDServiceClientCopyProperty.argtypes = [vp, vp]
    iokit.IOHIDServiceClientCopyEvent.restype = vp
    iokit.IOHIDServiceClientCopyEvent.argtypes = [vp, ctypes.c_int64, ctypes.c_int32, ctypes.c_int64]
    iokit.IOHIDEventGetFloatValue.restype = ctypes.c_double
    iokit.IOHIDEventGetFloatValue.argtypes = [vp, ctypes.c_int32]
    utf8 = 0x08000100

    def cfs(x):
        return cf.CFStringCreateWithCString(None, x.encode(), utf8)

    def cfn(v):
        n = ctypes.c_int32(v)
        return cf.CFNumberCreate(None, 3, ctypes.byref(n))

    kcb = ctypes.addressof(ctypes.c_char.in_dll(cf, "kCFTypeDictionaryKeyCallBacks"))
    vcb = ctypes.addressof(ctypes.c_char.in_dll(cf, "kCFTypeDictionaryValueCallBacks"))
    keys = (vp * 2)(cfs("PrimaryUsagePage"), cfs("PrimaryUsage"))
    vals = (vp * 2)(cfn(0xff00), cfn(5))
    match = cf.CFDictionaryCreate(None, keys, vals, 2, kcb, vcb)
    client = iokit.IOHIDEventSystemClientCreate(None)
    iokit.IOHIDEventSystemClientSetMatching(client, match)
    arr = iokit.IOHIDEventSystemClientCopyServices(client)
    if not arr:
        return None
    prod = cfs("Product")
    die, other = [], []
    for i in range(cf.CFArrayGetCount(arr)):
        svc = cf.CFArrayGetValueAtIndex(arr, i)
        name = ""
        ref = iokit.IOHIDServiceClientCopyProperty(svc, prod)
        if ref:
            buf = ctypes.create_string_buffer(128)
            if cf.CFStringGetCString(ref, buf, 128, utf8):
                name = buf.value.decode("utf-8", "replace").lower()
        ev = iokit.IOHIDServiceClientCopyEvent(svc, 15, 0, 0)    # 15 = temperature
        if not ev:
            continue
        v = iokit.IOHIDEventGetFloatValue(ev, 15 << 16)
        if not 0 < v < 150:
            continue
        if "tdie" in name:
            die.append(v)
        elif not any(w in name for w in ("battery", "gas", "nand")):
            other.append(v)
    if die:
        return sum(die) / len(die)
    return max(other) if other else None


if __name__ == "__main__":
    try:
        t = temp_read()
        if t is not None:
            print("TEMP|%.1f" % t)
    except Exception:
        pass
    sys.exit(0)
