// Drop-in replacement for Brother PED-Basic's CardIO.dll.
//
// The real DLL talks to a USB embroidery-card writer. This one exports the same
// nine __thiscall symbols and forwards every call to a Python module (cardio.py),
// which pretends to be a card writer and saves the card image to a file.
//
// Only the ABI lives here. All behaviour belongs in cardio.py -- the bridge hands
// Python raw pointers as integers and lets it do the work with ctypes.
//
// Must be built 32-bit: pelite.exe is x86 and every export is __thiscall.

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

// ---------------------------------------------------------------- logging --

static HMODULE g_hSelf;
static char    g_dllDir[MAX_PATH];
static char    g_logPath[MAX_PATH];

static void logf(const char *fmt, ...)
{
    FILE *f = fopen(g_logPath, "a");
    if (!f)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

// --------------------------------------------------------- CPython bridge --
//
// CPython is resolved at runtime rather than link time so the DLL builds and
// loads with no Python SDK present, and so a missing interpreter degrades to a
// clean error dialog instead of a failed process start.

typedef struct _object PyObject;

static HMODULE g_py;
static bool    g_pyReady;
static PyObject *g_module;

static void      (__cdecl *p_Py_InitializeEx)(int);
static int       (__cdecl *p_Py_IsInitialized)(void);
static void *    (__cdecl *p_PyEval_SaveThread)(void);
static int       (__cdecl *p_PyGILState_Ensure)(void);
static void      (__cdecl *p_PyGILState_Release)(int);
static int       (__cdecl *p_PyRun_SimpleString)(const char *);
static PyObject *(__cdecl *p_PyImport_ImportModule)(const char *);
static PyObject *(__cdecl *p_PyObject_CallMethod)(PyObject *, const char *, const char *, ...);
static long      (__cdecl *p_PyLong_AsLong)(PyObject *);
static void      (__cdecl *p_Py_DecRef)(PyObject *);
static PyObject *(__cdecl *p_PyErr_Occurred)(void);
static void      (__cdecl *p_PyErr_Print)(void);

#define RESOLVE(name)                                                    \
    do {                                                                 \
        *(FARPROC *)&p_##name = GetProcAddress(g_py, #name);             \
        if (!p_##name) {                                                 \
            logf("[bridge] missing export: %s", #name);                  \
            return false;                                                \
        }                                                                \
    } while (0)

static HMODULE load_python_dll(void)
{
    static const char *kNames[] = {
        "python314.dll", "python313.dll", "python312.dll", "python311.dll",
        "python310.dll", "python39.dll",  "python38.dll",  "python3.dll",
    };

    // 1. explicit override
    char override[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("CARDIO_PYTHON_DLL", override, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        HMODULE h = LoadLibraryA(override);
        if (h) {
            logf("[bridge] loaded %s (CARDIO_PYTHON_DLL)", override);
            return h;
        }
        logf("[bridge] CARDIO_PYTHON_DLL set but load failed: %s (err %lu)",
             override, GetLastError());
    }

    // 2. embeddable runtime shipped next to this DLL
    for (int i = 0; i < ARRAYSIZE(kNames); i++) {
        char path[MAX_PATH];
        _snprintf(path, MAX_PATH, "%s\\python-embed\\%s", g_dllDir, kNames[i]);
        path[MAX_PATH - 1] = 0;
        HMODULE h = LoadLibraryA(path);
        if (h) {
            logf("[bridge] loaded %s", path);
            return h;
        }
    }

    // 3. whatever is on PATH
    for (int i = 0; i < ARRAYSIZE(kNames); i++) {
        HMODULE h = LoadLibraryA(kNames[i]);
        if (h) {
            logf("[bridge] loaded %s (from PATH)", kNames[i]);
            return h;
        }
    }

    logf("[bridge] no 32-bit Python DLL found. Put an embeddable runtime in "
         "%s\\python-embed or set CARDIO_PYTHON_DLL.", g_dllDir);
    return NULL;
}

static bool py_init(void)
{
    if (g_pyReady)
        return true;
    if (g_py)           // a previous attempt already failed; don't retry
        return false;

    g_py = load_python_dll();
    if (!g_py)
        return false;

    RESOLVE(Py_InitializeEx);
    RESOLVE(Py_IsInitialized);
    RESOLVE(PyEval_SaveThread);
    RESOLVE(PyGILState_Ensure);
    RESOLVE(PyGILState_Release);
    RESOLVE(PyRun_SimpleString);
    RESOLVE(PyImport_ImportModule);
    RESOLVE(PyObject_CallMethod);
    RESOLVE(PyLong_AsLong);
    RESOLVE(Py_DecRef);
    RESOLVE(PyErr_Occurred);
    RESOLVE(PyErr_Print);

    bool weInitialized = false;
    if (!p_Py_IsInitialized()) {
        p_Py_InitializeEx(0);   // 0 = don't install signal handlers, we're a guest
        weInitialized = true;
    }

    int gil = p_PyGILState_Ensure();

    // cardio.py lives beside this DLL.
    char boot[MAX_PATH + 128];
    _snprintf(boot, sizeof(boot),
              "import sys\n"
              "p = r'%s'\n"
              "if p not in sys.path: sys.path.insert(0, p)\n",
              g_dllDir);
    boot[sizeof(boot) - 1] = 0;
    p_PyRun_SimpleString(boot);

    g_module = p_PyImport_ImportModule("cardio");
    if (!g_module) {
        logf("[bridge] failed to import cardio.py from %s", g_dllDir);
        if (p_PyErr_Occurred())
            p_PyErr_Print();
        p_PyGILState_Release(gil);
        return false;
    }

    p_PyGILState_Release(gil);
    if (weInitialized)
        p_PyEval_SaveThread();  // drop the GIL so PyGILState_Ensure works later

    g_pyReady = true;
    logf("[bridge] cardio.py ready");
    return true;
}

// Call cardio.<fn>(...) and return its int result, or `fallback` if anything
// goes wrong. `fmt` is a Py_BuildValue format string.
static int py_call(int fallback, const char *fn, const char *fmt, ...)
{
    if (!py_init())
        return fallback;

    int gil = p_PyGILState_Ensure();

    va_list ap;
    va_start(ap, fmt);
    // PyObject_CallMethod is __cdecl variadic; forwarding a va_list is not
    // possible through it, so pass the (at most five) integer args positionally.
    int a[5] = {0, 0, 0, 0, 0};
    for (int i = 0; fmt[i] && i < 5; i++)
        a[i] = va_arg(ap, int);
    va_end(ap);

    PyObject *r = p_PyObject_CallMethod(g_module, fn, (char *)fmt,
                                        a[0], a[1], a[2], a[3], a[4]);
    int rc = fallback;
    if (!r) {
        logf("[bridge] cardio.%s() raised", fn);
        if (p_PyErr_Occurred())
            p_PyErr_Print();
    } else {
        rc = (int)p_PyLong_AsLong(r);
        p_Py_DecRef(r);
    }

    p_PyGILState_Release(gil);
    return rc;
}

// ------------------------------------------------------------ CardIO ABI --
//
// These declarations exist to make the C++ compiler emit exactly the mangled
// names the original DLL exported. Do not rename anything: the symbol *is* the
// interface. CardIO.def pins the names and ordinals; build.bat verifies them.

enum CIOError {
    IO_OK             = 0x18,  // the one value pelite.exe treats as success
    IO_NOT_CONNECTED  = 0x01,
    IO_NO_CARD        = 0x03,
    IO_WRONG_CARD     = 0x04,
    IO_CARD_BUSY      = 0x05,
    IO_TOO_LARGE      = 0x06,
    IO_NO_MEMORY      = 0x0B,
    IO_BAD_VOLUME     = 0x17,
};

enum CCardAtrbType { };   // hoop-size index, 0..4
class CObArray;           // MFC array of the patterns being written

class CCardIO {
public:
    CCardIO(int cardType);
    ~CCardIO();
    CCardIO &operator=(const CCardIO &rhs);

    CIOError ChkCardVolume(CObArray &patterns, int &total, int &used, CCardAtrbType *atrb);
    CIOError ChkCardWriterConnected(int port, unsigned char *version, int *out);
    CIOError Receive(CObArray *patterns, int arg, const void *progressFn, const void *progressCtx);
    void     ResetCardID();
    CIOError Send(CObArray &patterns, const void *progressFn, const void *progressCtx,
                  CCardAtrbType *atrb);
    CIOError WriteExecutableNum(int n);

private:
    unsigned char m_cardId[3];   // ResetCardID() zeroes exactly these three bytes
    unsigned char m_pad;
    int           m_cardType;    // ctor argument; selects card geometry downstream
};

// pelite.exe does `operator new(8)` for this object -- the layout must match.
C_ASSERT(sizeof(CCardIO) == 8);

CCardIO::CCardIO(int cardType)
{
    m_cardId[0] = m_cardId[1] = m_cardId[2] = 0;
    m_pad = 0;
    m_cardType = cardType;
    logf("CCardIO(%d) this=%p", cardType, this);
    py_call(0, "create", "ii", (int)this, cardType);
}

CCardIO::~CCardIO()
{
    py_call(0, "destroy", "i", (int)this);
}

CCardIO &CCardIO::operator=(const CCardIO &rhs)
{
    m_cardId[0] = rhs.m_cardId[0];
    m_cardId[1] = rhs.m_cardId[1];
    m_cardId[2] = rhs.m_cardId[2];
    m_pad       = rhs.m_pad;
    m_cardType  = rhs.m_cardType;
    return *this;
}

void CCardIO::ResetCardID()
{
    m_cardId[0] = m_cardId[1] = m_cardId[2] = 0;
    py_call(0, "reset_card_id", "i", (int)this);
}

CIOError CCardIO::ChkCardWriterConnected(int port, unsigned char *version, int *out)
{
    return (CIOError)py_call(IO_NOT_CONNECTED, "chk_card_writer_connected", "iiii",
                             (int)this, port, (int)version, (int)out);
}

CIOError CCardIO::ChkCardVolume(CObArray &patterns, int &total, int &used, CCardAtrbType *atrb)
{
    return (CIOError)py_call(IO_NOT_CONNECTED, "chk_card_volume", "iiiii",
                             (int)this, (int)&patterns, (int)&total, (int)&used, (int)atrb);
}

CIOError CCardIO::Send(CObArray &patterns, const void *progressFn, const void *progressCtx,
                       CCardAtrbType *atrb)
{
    return (CIOError)py_call(IO_NOT_CONNECTED, "send", "iiiii",
                             (int)this, (int)&patterns, (int)progressFn,
                             (int)progressCtx, (int)atrb);
}

CIOError CCardIO::Receive(CObArray *patterns, int arg, const void *progressFn,
                          const void *progressCtx)
{
    return (CIOError)py_call(IO_NOT_CONNECTED, "receive", "iiiii",
                             (int)this, (int)patterns, arg,
                             (int)progressFn, (int)progressCtx);
}

CIOError CCardIO::WriteExecutableNum(int n)
{
    return (CIOError)py_call(IO_NOT_CONNECTED, "write_executable_num", "ii", (int)this, n);
}

// ----------------------------------------------------------------- DllMain --

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hSelf = (HMODULE)hInst;
        DisableThreadLibraryCalls(hInst);

        GetModuleFileNameA(g_hSelf, g_dllDir, MAX_PATH);
        char *slash = strrchr(g_dllDir, '\\');
        if (slash)
            *slash = 0;
        _snprintf(g_logPath, MAX_PATH, "%s\\cardio-py.log", g_dllDir);
        g_logPath[MAX_PATH - 1] = 0;

        // Deliberately no Python work here: initialising an interpreter under
        // the loader lock deadlocks. py_init() runs on the first real call.
        logf("---- CardIO.dll (python shim) attached ----");
    }
    return TRUE;
}
