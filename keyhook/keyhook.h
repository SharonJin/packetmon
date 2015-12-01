#pragma once

#ifdef keyhook_dll
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif

EXPORT void CALLBACK keyhook_install();
EXPORT void CALLBACK keyhook_uninstall();

#pragma data_seg(".kshare")
namespace shared {
    extern HHOOK _hook;
    EXPORT extern int keyhook_vk;
    EXPORT extern bool keyhook_enabled;
}
#pragma data_seg()
