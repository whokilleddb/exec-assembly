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
extern "C" int run_assembly(unsigned char* f_bytes, size_t f_size, wchar_t * argv[], int count) {
    int _res = 0;
    VARIANT obj, retval, args;
    HRESULT hr;
    ICLRMetaHost* metahost = NULL;
    IEnumUnknown* runtime = NULL;
    ICLRRuntimeInfo* runtimeInfo = NULL;
    ICorRuntimeHost* runtimeHost = NULL;
    IUnknown* enumRuntime = NULL;
    IUnknown* defaultRuntime = NULL;
    LPWSTR frameworkName = NULL;
    DWORD bytes = 2048, result = 0;
    SAFEARRAY* b_payload = NULL;
    ULONG entryPoint = 1;
    long idx[1];
    SAFEARRAYBOUND bnd_payload;
    mscorlib::_AppDomainPtr appDomain = nullptr;
    mscorlib::_AssemblyPtr  dotnetAssembly = nullptr;
    mscorlib::_MethodInfoPtr methodInfo = nullptr;


    // Initialize variants
    ZeroMemory(&obj, sizeof(VARIANT));
    ZeroMemory(&retval, sizeof(VARIANT));
    ZeroMemory(&args, sizeof(VARIANT));
    obj.vt = VT_NULL;

    // Set command line arguments
    args.vt = VT_ARRAY | VT_BSTR;

    SAFEARRAYBOUND argsBound[1];
    argsBound[0].lLbound = 0;
    argsBound[0].cElements = count;
    args.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
    //assert(args.parray);
    for (int i = 0; i < count; i++)
    {
        idx[0] = i;
        SafeArrayPutElement(args.parray, idx, SysAllocString(argv[i]));
    }

    SAFEARRAY* params = NULL;
    SAFEARRAYBOUND paramsBound[1];
    paramsBound[0].lLbound = 0;
    paramsBound[0].cElements = 1;
    params = SafeArrayCreate(VT_VARIANT, 1, paramsBound);

    idx[0] = { 0 };
    SafeArrayPutElement(params, idx, &args);


    // Create CLR Interface
    hr = CLRCreateInstance(
        CLSID_CLRMetaHost,          // Class Identifer for CLR
        IID_ICLRMetaHost,           // Interface Identifier for CLR
        (LPVOID*)&metahost);       // COM interface for CLR

    if (hr != S_OK) {
        EPRINT("!> CLRCreateInstance() Failed 0x%x", hr);
        return -1;
    }

    // Enumerate Installed Runtimes
    hr = metahost->EnumerateInstalledRuntimes(&runtime);
    if (hr != S_OK) {
        _res = -2;
        EPRINT("!> Failed to Enumerate Installed Runtimes (0x%x)", hr);
        goto cleanup;
    }

    // Print Installed Runtimes
    frameworkName = (LPWSTR)LocalAlloc(LPTR, 2048 * 2);
    if (frameworkName == NULL) {
        _res = -3;
        EPRINT("!> LocalAlloc Failed (0x%x)", hr);
        goto cleanup;
    }


    // Enumerate through runtimes and show supported frameworks
    while (runtime->Next(1, &enumRuntime, 0) == S_OK) {
        if (enumRuntime->QueryInterface<ICLRRuntimeInfo>(&runtimeInfo) == S_OK) {
            if (runtimeInfo != NULL) {
                runtimeInfo->GetVersionString(frameworkName, &bytes);
                wprintf(L"i> Supported Framework: %s\n", frameworkName);
            }
        }
        enumRuntime->Release();
    }


    // Check if runtime is loadable
    BOOL bLoadable;
    hr = runtimeInfo->IsLoadable(&bLoadable);

    if (hr != S_OK || !bLoadable) {
        _res = -4;
        EPRINT("!> Runtime is not Loadable! (0x%x)", hr);
        goto cleanup;
    }
    PRINT("i> Runtime is Loadable!");

    // Use the last supported runtime
    hr = runtimeInfo->GetInterface(
        CLSID_CorRuntimeHost,
        IID_ICorRuntimeHost,
        (LPVOID*)&runtimeHost);

    if (hr != S_OK) {
        _res = -5;
        EPRINT("i> GetInterface(CLSID_CLRRuntimeHost) failed (0x%x)", hr);
        goto cleanup;
    }

    // Start CLR
    PRINT("i> Starting CLR");
    runtimeHost->Start();

    // Use Default AppDomain
    hr = runtimeHost->GetDefaultDomain(&defaultRuntime);
    if (hr != S_OK) {
        _res = -6;
        EPRINT("i> Failed to get Default AppDomain (0x%x)", hr);
        goto cleanup;
    }

    hr = defaultRuntime->QueryInterface(IID_PPV_ARGS(&appDomain));
    if (hr != S_OK) {
        _res = -7;
        EPRINT("i> Failed to get Query Interface for Default AppDomain (0x%x)", hr);
        goto cleanup;
    }

    // Create SafeArray
    bnd_payload.lLbound = 0;
    bnd_payload.cElements = f_size;
    PRINT("i> Creating SafeArray");
    b_payload = SafeArrayCreate(VT_UI1, 1, &bnd_payload);
    if (b_payload == NULL) {
        _res = -8;
        EPRINT("i> SafeArrayCreate() failed (0x%x)", hr);
        goto cleanup;
    }

    // Copying Payload to SafeArray
    CopyMemory(b_payload->pvData, f_bytes, f_size);
    PRINT("i> Copied Payload to SafeArray!");

    // Prepare AppDomain and Entrypoint
    hr = appDomain->Load_3(b_payload, &dotnetAssembly);
    if (hr != S_OK) {
        _res = -8;
        EPRINT("i> Failed to Load Assembly (0x%x)", hr);
        goto cleanup;
    }

    // Get EntryPoint
    hr = dotnetAssembly->get_EntryPoint(&methodInfo);
    if (hr != S_OK) {
        _res = -9;
        EPRINT("i> Failed to get EntryPoint (0x%x)", hr);
        goto cleanup;
    }

    // Invoke Entrypoint function
    PRINT("i> Invoking Entrypoint\n");
    PRINT("==== Entering Managed Code Land ====\n");

    hr = methodInfo->Invoke_3(obj, params, &retval);
    if (hr != S_OK) {
        _res = -10;
        EPRINT("!> Invoke_3() Failed (0x%x)", hr);
    }
    PRINT("\n==== Exiting Managed Code Land ====");

    // Clean Up
cleanup:
    VariantClear(&obj);
    VariantClear(&retval);
    VariantClear(&args);
    PRINT("i> Cleaning Up!");

    if (methodInfo != nullptr) {
        methodInfo->Release();
    }

    if (dotnetAssembly != nullptr) {
        dotnetAssembly->Release();
    }

    if (b_payload != NULL) {
        SafeArrayDestroy(b_payload);
    }

    if (appDomain != NULL) {
        appDomain->Release();
    }

    if (defaultRuntime != NULL) {
        defaultRuntime->Release();
    }

    // Stop CLR
    PRINT("i> Stopping CLR");
    runtimeHost->Stop();

    if (runtimeHost != NULL) {
        runtimeHost->Release();
    }

    if (frameworkName != NULL) {
        LocalFree(frameworkName);
    }

    if (runtimeInfo != NULL) {
        runtimeInfo->Release();
    }

    if (runtime != NULL) {
        runtime->Release();
    }


    if (metahost != NULL) {
        metahost->Release();
    }


    PRINT("i> Cleanup Done!");
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
    PRINT("i> Loading Assembly from: %s", argv[1]);

    // Get file contents
    unsigned char* f_bytes = read_file(argv[1]);
    if (f_bytes == NULL) {
        EPRINT("!> Failed to read assembly");
        return -1;
    }

    PRINT("i> Read %" PRId64 " bytes", _msize(f_bytes));

    int nArgs;
    wchar_t* hi = L"LastShutDown";
    LPWSTR * arr = CommandLineToArgvW(hi, &nArgs);

    int res = run_assembly(f_bytes, _msize(f_bytes), arr , nArgs);
    if (res != 0) {
        EPRINT("!> Failed to run Assembly");
        free(f_bytes);
        return -2;
    }

    free(f_bytes);
    return 0;
}

