// PoC for running .NET Assemblies in-memory, similar to Cobat Strike's `exeute-assembly` 
// Note: CS loads assemblies in a Custom domain, while this PoC runs it in the Deafult AppDomain
//
// Compile with: cl in-mem-dnet.cpp

#include <windows.h>
#include <iostream>
#include <inttypes.h>
#include <comdef.h>
#include <mscoree.h>
#include <metahost.h>

#pragma comment(lib, "mscoree.lib")
#import "mscorlib.tlb" raw_interfaces_only

#define APPDOMAIN_NAME  "secret_santa"

using namespace mscorlib;

#define PRINT(...) { \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n"); \
}


#define EPRINT(...) { \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
}

// Function to read assembly from file
unsigned char* read_file(char* file_name) {
    HANDLE hfile;
    DWORD ho_fsz, lo_fsz;

    // Open file for reading
    hfile = CreateFileA(
        file_name,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hfile == INVALID_HANDLE_VALUE) {
        EPRINT("!> Could not open %s for reading(0x%x)", file_name, GetLastError());
        return NULL;
    }

    // Get File Size
    lo_fsz = GetFileSize(hfile, &ho_fsz);
    if (lo_fsz == INVALID_FILE_SIZE) {
        EPRINT("!> Failed to get file size (0x%x)", GetLastError());
        CloseHandle(hfile);
        return NULL;
    }

    // Allocate memory
    unsigned char* s_bytes = (unsigned char*)malloc(lo_fsz);
    if (s_bytes == NULL) {
        EPRINT("!> Malloc() failed (0x%x)", GetLastError());
        CloseHandle(hfile);
        return NULL;
    }

    // Read File
    BOOL result = ReadFile(
        hfile,
        s_bytes,
        lo_fsz,
        &ho_fsz,
        NULL
    );

    if (!result) {
        EPRINT("!> Failed to read\t%s (0x%x)", file_name, GetLastError());
        free(s_bytes);
        CloseHandle(hfile);
        return NULL;
    }
    CloseHandle(hfile);
    return s_bytes;
    return NULL;
}

// Function to run assembly
extern "C" int run_assembly(unsigned char* f_bytes, size_t f_size, char * cli_args) {
    HRESULT hr;
    wchar_t * w_args = NULL;
    LPWSTR * w_cli_args = NULL;
    int args_count, _res = 0, _out = 0 ;

    long idx[1];
    VARIANT obj, retval, args;
    SAFEARRAYBOUND argsBound[1];

    SAFEARRAY* params = NULL;
    SAFEARRAYBOUND paramsBound[1];

    SAFEARRAYBOUND bnd_payload;
    SAFEARRAY* b_payload = NULL;

    ICLRMetaHost* pMetaHost = NULL;
    IEnumUnknown* runtime = NULL;
    LPWSTR frameworkName = NULL;

    IUnknown* enumRuntime = NULL;
    ICLRRuntimeInfo* runtimeInfo = NULL;
    
    BOOL bLoadable;
    ICorRuntimeHost* runtimeHost = NULL;
    IUnknown* appDomainThunk = NULL;
    _AppDomainPtr appDomain = nullptr;

    IUnknown* defaultRuntime = NULL;
    DWORD bytes = 2048, result = 0;
    ULONG entryPoint = 1;
    _AssemblyPtr  dotnetAssembly = nullptr;
    _MethodInfoPtr methodInfo = nullptr;

    // Print Arguments passed to function for Debug Builds
    #ifdef _DEBUG
        PRINT("================= run_assembly() =================");
        PRINT("[i] Address of Assembly:\t%p", f_bytes);
        PRINT("[i] Size of Assembly:\t\t%d", f_size);
        PRINT("[i] Value of CLI Args:\t\t%s", cli_args);
        PRINT("[i] Address of CLI Args:\t%p", cli_args);
    #endif

    // Converting CLI args to Wide String
    w_args = (wchar_t*)malloc((strlen(cli_args) + 1) * 2);
    if (w_args == NULL) {
        _res = 1;
        EPRINT("[i] Malloc() failed (0x%x)", GetLastError());
        goto cleanup;
    }
    #ifdef _DEBUG
        PRINT("\n[i] Allocated Memory for Wide CLI Args");
        PRINT("[i] Allocated Address:\t%p", w_args);
        PRINT("[i] Allocated Size:\t%d", _msize(w_args));
    #endif

    // Zeroing out memory location
    RtlZeroMemory(w_args, _msize(w_args));

    // Convert CLI Args to Wide Chars
    _out = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, cli_args, -1, w_args, _msize(w_args));
    if (_out != (strlen(cli_args) + 1)) {
		_res = -2;
		EPRINT("[x] MultiByteToWideChar() failed (0x%x)", GetLastError());
        goto cleanup;
	}

    #ifdef _DEBUG
        PRINT("[i] Bytes converted:\t%d", _out);
    #endif

    // Convert Wide Chars to CLI Args
    w_cli_args = CommandLineToArgvW(w_args, &args_count);
    if (w_cli_args == NULL) {
        _res = -3;
        EPRINT("[x] CommandLineToArgvW() failed (0x%x)", GetLastError());
        goto cleanup;
    }

    #ifdef _DEBUG
        PRINT("\n[i] Converted Wide Chars to CLI Args");
        PRINT("[i] Address of Args:\t%p", w_cli_args);
        PRINT("[i] Argument Count:\t%d\n", args_count);
    #endif

    // Creating SafeArray with CLI Args
    // Initialize variants
    ZeroMemory(&obj, sizeof(VARIANT));
    ZeroMemory(&retval, sizeof(VARIANT));
    ZeroMemory(&args, sizeof(VARIANT));
    obj.vt = VT_NULL;

    // Create SafeArray For command line args
    args.vt = VT_ARRAY | VT_BSTR;
    argsBound[0].lLbound = 0;
    argsBound[0].cElements = args_count;
    args.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
    if (args.parray == NULL) {
        EPRINT("[x] SafeArrayCreate() failed (0x%x)", GetLastError());
        _res = -4;
        goto cleanup;
    }

    #ifdef _DEBUG
        PRINT("[i] Created SafeArray to store CL Args at: %p", args.parray);
    #endif

    // Put elements in safe array
    for (int i = 0; i < args_count; i++) {
        idx[0] = i;
        hr = SafeArrayPutElement(args.parray, idx, SysAllocString(w_cli_args[i]));
        if (hr != S_OK) {
            EPRINT("[x] SafeArrayPutElement() Failed to Push %S (0x%x)", w_cli_args[i], hr);
            _res = -5;
            goto cleanup;
        }
    }

    #ifdef _DEBUG
        PRINT("[i] Put CLI Args in SafeArray");
    #endif

    // Create SafeArray to hold assembly
    // Store CLI Args
    paramsBound[0].lLbound = 0;
    paramsBound[0].cElements = 1;
    params = SafeArrayCreate(VT_VARIANT, 1, paramsBound);
    if (params == NULL) {
        EPRINT("[x] SafeArrayCreate() failed (0x%x)", GetLastError());
        _res = -6;
        goto cleanup;
    }

    #ifdef _DEBUG
        PRINT("\n[i] Created SafeArray to hold CLI Args Variant at: %p", params);
    #endif

    // Put Argument object in safe array
    idx[0] = { 0 };
    hr = SafeArrayPutElement(params, idx, &args);
    if (hr != S_OK) {
        EPRINT("[x] SafeArrayPutElement() Failed to Push CLI Args variant (0x%x)", hr);
        _res = -7;
        goto cleanup;
    }
    #ifdef _DEBUG
        PRINT("[i] Inserted CLI Args Variant in SafeArray");
    #endif
    

    // Create SafeArrayc to hold Assembly Buffer
    bnd_payload.lLbound = 0;
    bnd_payload.cElements = f_size;
    b_payload = SafeArrayCreate(VT_UI1, 1, &bnd_payload);
    if (b_payload == NULL) {
        _res = -8;
        EPRINT("[i] SafeArrayCreate() failed (0x%x)", GetLastError());
        goto cleanup;
    }

    #ifdef _DEBUG
        PRINT("[i] Created SafeArray to hold Assembly at: %p", b_payload);
    #endif

    // Copying Payload to SafeArray
    SafeArrayAccessData(b_payload, &(b_payload->pvData));
    CopyMemory(b_payload->pvData, f_bytes, f_size);
    SafeArrayUnaccessData(b_payload);
    
    #ifdef _DEBUG
        PRINT("[i] Copied Payload to SafeArray!");
        PRINT("[i] Data Copied at:\t%p\n", b_payload->pvData);
    #endif

    // Create CLR Interface
    hr = CLRCreateInstance(
        CLSID_CLRMetaHost,          // Class Identifer for CLR
        IID_ICLRMetaHost,           // Interface Identifier for CLR
        (LPVOID*)&pMetaHost);       // COM interface for CLR

    if (hr != S_OK) {
        EPRINT("[x] CLRCreateInstance() Failed 0x%x", hr);
        _res = -9;
        goto cleanup;
    }
    PRINT("[i] Created CLR MetaHost");

    // Enumerate Installed Runtimes
    hr = pMetaHost->EnumerateInstalledRuntimes(&runtime);
    if (hr != S_OK) {
        _res = -10;
        EPRINT("[x] Failed to Enumerate Installed Runtimes (0x%x)", hr);
        goto cleanup;
    }

    // Print Installed Runtimes
    frameworkName = (LPWSTR)LocalAlloc(LPTR, 2048 * 2);
    if (frameworkName == NULL) {
        _res = -11;
        EPRINT("[x] LocalAlloc Failed (0x%x)", GetLastError());
        goto cleanup;
    }
    #ifdef _DEBUG
        PRINT("[i] Allocated Memory to hold runtime names at: %p",  frameworkName);
    #endif
    RtlZeroMemory(frameworkName, 2048 * 2);

    // Enumerate through runtimes and show supported frameworks
    while (runtime->Next(1, &enumRuntime, 0) == S_OK) {
        if (enumRuntime->QueryInterface<ICLRRuntimeInfo>(&runtimeInfo) == S_OK) {
            if (runtimeInfo != NULL) {
                runtimeInfo->GetVersionString(frameworkName, &bytes);
                wprintf(L"[x] Supported Framework: %s\n", frameworkName);
            }
        }
        enumRuntime->Release();
    }

    hr = pMetaHost->GetRuntime(frameworkName, IID_ICLRRuntimeInfo, (VOID**)&runtimeInfo);
    if (hr != S_OK) {
        PRINT("OOPS")
    }

    // Check if runtime is loadable
    hr = runtimeInfo->IsLoadable(&bLoadable);

    if (hr != S_OK || !bLoadable) {
        _res = -12;
        EPRINT("[x] Runtime is not Loadable! (0x%x)", hr);
        goto cleanup;
    }
    PRINT("[i] Runtime is Loadable!");

    // Use the last supported runtime
    hr = runtimeInfo->GetInterface(
        CLSID_CorRuntimeHost,
        IID_ICorRuntimeHost,
        (LPVOID*)&runtimeHost);

    if (hr != S_OK) {
        _res = -13;
        EPRINT("[x] GetInterface(CLSID_CLRRuntimeHost) failed (0x%x)", hr);
        goto cleanup;
    }

    #ifdef _DEBUG
        PRINT("[i] Fetched RunTimeHost\n")
    #endif

    // Start CLR
    PRINT("[i] Starting CLR!");
    runtimeHost->Start();

    // Create Custom AppDomain
    hr = runtimeHost->CreateDomain(L"huiohui", NULL, &appDomainThunk);
    if (hr != S_OK) {
        _res = -14;
        EPRINT("[i] Failed to create AppDomain (0x%x)", hr);
        goto cleanup;
    }

    hr = appDomainThunk->QueryInterface(IID_PPV_ARGS(&appDomain));
    if (hr != S_OK) {
        _res = -15;
        EPRINT("[i] Failed to get Query Interface for AppDomain (0x%x)", hr);
        goto cleanup;
    }

    // Prepare AppDomain and Entrypoint
    hr = appDomain->Load_3(b_payload, &dotnetAssembly);
    if (hr != S_OK) {
        _res = -16;
        EPRINT("[x] Failed to Load Assembly (0x%x)", hr);
        goto cleanup;
    }

    PRINT("[i] Loaded Assembly Into Domain!")

    // Get EntryPoint
    hr = dotnetAssembly->get_EntryPoint(&methodInfo);
    if (hr != S_OK) {
        _res = -17;
        EPRINT("[x] Failed to get EntryPoint (0x%x)", hr);
        goto cleanup;
    }

    // Invoke Entrypoint function
    PRINT("[i] Invoking Entrypoint\n");
    PRINT("==== Entering Managed Code Land ====\n");

    hr = methodInfo->Invoke_3(obj, params, &retval);
    if (hr != S_OK) {
        _res = -18;
        EPRINT("[x] Invoke_3() Failed (0x%x)", hr);
    }
    PRINT("\n==== Exiting Managed Code Land ====");

    cleanup:
        PRINT("\n[i] Cleaning Up!");
        if (w_args != NULL) {
            #ifdef _DEBUG
                PRINT("[i] Freeing Memory occuied by Wide CLI Args");
            #endif
            free(w_args);
        }

        // Clearing Variants
        #ifdef _DEBUG
            PRINT("[i] Clearing Variants");
        #endif
        VariantClear(&obj);
        VariantClear(&retval);
        VariantClear(&args);

        if (params != NULL) {
            SafeArrayDestroy(params);
        }

        if (b_payload != NULL) {
            SafeArrayDestroy(b_payload);
        }

    if (methodInfo != nullptr) {
        methodInfo->Release();
    }

    if (dotnetAssembly != nullptr) {
        dotnetAssembly->Release();
    }

    if (appDomain != NULL) {
        appDomain->Release();
    }

    if (appDomainThunk != NULL) {
        appDomainThunk->Release();
    }

    // Stop CLR
    runtimeHost->Stop();

    if (runtimeHost != NULL) {
        runtimeHost->Release();
    }


    if (runtimeInfo != NULL) {
        runtimeInfo->Release();
    }

    if (frameworkName != NULL) {
        LocalFree(frameworkName);
    }

    if (runtime != NULL) {
        runtime->Release();
    }

    if (pMetaHost != NULL) {
        pMetaHost->Release();
    }


//     PRINT("i> Cleanup Done!");
    return _res;
}

int main(int argc, char** argv) {
    PRINT("==== Run .NET in-memory ====");

    // Check arguments
    if (argc == 1) {
        EPRINT("!> Invalid Arguments");
        EPRINT("!> Usage: %s <ASSEMBLY PATH>", argv[0]);
        return -1;
    }

    // Print File path
    PRINT("[i] Loading Assembly from: %s", argv[1]);

    // Get file contents
    unsigned char* f_bytes = read_file(argv[1]);
    if (f_bytes == NULL) {
        EPRINT("[x] Failed to read assembly");
        return -1;
    }

    PRINT("[x] Read %" PRId64 " bytes", _msize(f_bytes));

    int res = run_assembly(f_bytes, _msize(f_bytes), "LastShutDown");
    if (res != 0) {
        EPRINT("[x] Failed to run Assembly");
        free(f_bytes);
        return -2;
    }

    free(f_bytes);
    return 0;
}

