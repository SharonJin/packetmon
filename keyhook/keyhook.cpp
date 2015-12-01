#define keyhook_dll
#include <windows.h>
#include "keyhook.h"

HINSTANCE _hinst;

#pragma data_seg(".kshare")
namespace shared {
    HHOOK _hook = NULL;
    EXPORT int keyhook_vk = 0;
    EXPORT bool keyhook_enabled = false;
}
#pragma data_seg()
#pragma comment(linker, "/section:.kshare,RWS")

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        _hinst = hinst;
    }
    return TRUE;
}

LRESULT CALLBACK CallKeyboardProc(int code, WPARAM wp, LPARAM lp) {
    if (code < 0)
        return CallNextHookEx(shared::_hook, code, wp, lp);

    if (shared::keyhook_enabled == 1 && wp == shared::keyhook_vk)
        return 1;

    return CallNextHookEx(shared::_hook, code, wp, lp);
}

EXPORT void CALLBACK keyhook_install() {
    shared::_hook = SetWindowsHookEx(WH_KEYBOARD, CallKeyboardProc, _hinst, 0);
}

EXPORT void CALLBACK keyhook_uninstall() {
    UnhookWindowsHookEx(shared::_hook);
}