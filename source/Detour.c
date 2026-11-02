/*
 * GoldHEN Plugin SDK - a prx hook/patch sdk for Orbis OS
 *
 * Credits
 * - OSM <https://github.com/OSM-Made>
 * - jocover <https://github.com/jocover>
 * - bucanero <https://github.com/bucanero>
 * - OpenOrbis Team <https://github.com/OpenOrbis>
 * - SiSTRo <https://github.com/SiSTR0>
 */

#include "Common.h"
#include "HDE64.h"

#define DETOUR_PAGE_SIZE 0x1000ul
#define DETOUR_READ_SPAN 32

static int Detour_Unprotect(const char *Caller, uint64_t Address, size_t Size);
size_t Detour_GetInstructionSize(Detour *This, uint64_t Address, size_t MinSize);
void Detour_WriteJump64(Detour *This, void *Address, uint64_t Destination);
void Detour_WriteJump32(Detour *This, void *Address, uint64_t Destination);
void Detour_WriteJump16(Detour *This, void *Address);
uint64_t Detour_GetJumpAddress64(Detour *This, void *Address);
void *Detour_DetourFunction(Detour *This, uint64_t FunctionPtr, void *HookPtr);
void *Detour_DetourFunction64(Detour *This, uint64_t FunctionPtr, void *HookPtr);
void *Detour_DetourFunction32(Detour *This, uint64_t FunctionPtr, void *HookPtr);
void *Detour_DetourFunction16(Detour *This, uint64_t FunctionPtr, void *HookPtr);
void Detour_RestoreFunction(Detour *This);
void Detour_Construct(Detour *This, DetourMode Mode);
void Detour_Destroy(Detour *This);

static int Detour_Unprotect(const char *Caller, uint64_t Address, size_t Size) {
    uint64_t Start = Address & ~(DETOUR_PAGE_SIZE - 1);
    uint64_t End = (Address + Size + DETOUR_PAGE_SIZE - 1) & ~(DETOUR_PAGE_SIZE - 1);

    int res = sceKernelMprotect((void *) Start, End - Start, VM_PROT_ALL);
    if (res < 0) {
        klog("[Detour] %s: sceKernelMprotect(0x%lx, 0x%lx) failed (0x%x).\n", Caller, Start, End - Start, res);
    }
    return res;
}

size_t Detour_GetInstructionSize(Detour *This, uint64_t Address, size_t MinSize) {
    size_t InstructionSize = 0;

    if (!Address) return 0;

    while (InstructionSize < MinSize) {
        hde64s hs;
        uint32_t temp = hde64_disasm((void *) (Address + InstructionSize), &hs);

        if (hs.flags & F_ERROR) return 0;

        InstructionSize += temp;
    }

    return InstructionSize;
}

void Detour_WriteJump64(Detour *This, void *Address, uint64_t Destination) {
    // Write the address of our hook to the instruction.
    *(uint64_t * )(This->JumpInstructions64 + 6) = Destination;

    Detour_Unprotect(__FUNCTION__, (uint64_t) Address, sizeof(This->JumpInstructions64));
    memcpy(Address, This->JumpInstructions64, sizeof(This->JumpInstructions64));
}

void Detour_WriteJump32(Detour *This, void *Address, uint64_t Destination) {
    uint64_t Offset = (uint64_t)(Destination - ((uint64_t) Address + sizeof(This->JumpInstructions32)));
    if (Offset != (uint32_t)Offset) {
        klog("[Detour] %s: offset 0x%lx is too large!\n", __FUNCTION__, Offset);
    }

    // Write the address of our hook to the instruction.
    *(uint32_t * )(This->JumpInstructions32 + 1) = (uint32_t)Offset;

    Detour_Unprotect(__FUNCTION__, (uint64_t) Address, sizeof(This->JumpInstructions32));
    memcpy(Address, This->JumpInstructions32, sizeof(This->JumpInstructions32));
}

void Detour_WriteJump16(Detour* This, void* Address) {
    Detour_Unprotect(__FUNCTION__, (uint64_t) Address, sizeof(This->JumpInstructions16));
    memcpy(Address, This->JumpInstructions16, sizeof(This->JumpInstructions16));
}

uint64_t Detour_GetJumpAddress64(Detour *This, void *Address) {
    return *(uint64_t * )((uint64_t)Address + 6);
}

void* PATCH_BASE = (void*)0x800000000ul;

#define DETOUR_POOL_SIZE 0x40000

static uint8_t *Detour_Pool;
static size_t Detour_PoolUsed;
static volatile int Detour_PoolLock;

static int Detour_Alloc(size_t Size, void **Out) {
    int res = 0;
    Size = (Size + 15) & ~(size_t)15;

    while (__sync_lock_test_and_set(&Detour_PoolLock, 1)) {
    }

    if (!Detour_Pool) {
        void *Base = NULL;
        res = sceKernelMmap(PATCH_BASE, DETOUR_POOL_SIZE, VM_PROT_ALL, 0x2000 | 0x1000, -1, 0, &Base);
        if (res >= 0 && Base != NULL) {
            Detour_Pool = (uint8_t *) Base;
            res = 0;
        } else if (res >= 0) {
            res = -1;
        }
    }

    if (res == 0 && Detour_PoolUsed + Size > DETOUR_POOL_SIZE) {
        res = -1;
    }

    if (res == 0) {
        *Out = Detour_Pool + Detour_PoolUsed;
        Detour_PoolUsed += Size;
    }

    __sync_lock_release(&Detour_PoolLock);
    return res;
}

void *Detour_DetourFunction(Detour *This, uint64_t FunctionPtr, void *HookPtr) {
    if (!FunctionPtr  || !HookPtr) {
        klog("[Detour] %s: FunctionPtr or HookPtr NULL (%p -> %p)\n", __FUNCTION__, (void*)FunctionPtr, HookPtr);
        return NULL;
    }

    if (Detour_Unprotect(__FUNCTION__, FunctionPtr, DETOUR_READ_SPAN) < 0) return NULL;

    // Some functions start with a 32-bit relative jump. Instead of writing to this jump,
    // write the Detour to the jump location instead.
    if (*(uint8_t*)FunctionPtr == 0xE9) {
        uint64_t original = FunctionPtr;
        int offset = *(uint32_t*)(FunctionPtr + 1);
        // patch the function it jumps to.
        FunctionPtr += sizeof(This->JumpInstructions32) + offset;
        klog("[Detour] %s: Redirecting hook from 0x%lx to 0x%lx\n", __FUNCTION__, original, FunctionPtr);

        if (Detour_Unprotect(__FUNCTION__, FunctionPtr, DETOUR_READ_SPAN) < 0) return NULL;
    }

    switch (This->Mode) {
        case DetourMode_x16:
            return Detour_DetourFunction16(This, FunctionPtr, HookPtr);
        case DetourMode_x32:
            return Detour_DetourFunction32(This, FunctionPtr, HookPtr);
        case DetourMode_x64:
            return Detour_DetourFunction64(This, FunctionPtr, HookPtr);
    }
    return NULL;
}

void *Detour_DetourFunction64(Detour *This, uint64_t FunctionPtr, void *HookPtr) {
    uint32_t InstructionSize = Detour_GetInstructionSize(This, FunctionPtr, sizeof(This->JumpInstructions64));

    if (InstructionSize < sizeof(This->JumpInstructions64)) {
        klog("[Detour] %s: InstructionSize: %u\n", __FUNCTION__, InstructionSize);
        klog("[Detour] %s: Hooking Requires a minimum of %d bytes to write jump!\n", __FUNCTION__, (int)sizeof(This->JumpInstructions64));
        return NULL;
    }

    int res = Detour_Alloc(sizeof(This->JumpInstructions64), &This->TrampolinePtr);
    if (res < 0 || This->TrampolinePtr == 0) {
        klog("[Detour] %s: sceKernelMmap failed (0x%x).\n", __FUNCTION__, res);
        return 0;
    }

    Detour_WriteJump64(This, This->TrampolinePtr, (uint64_t) HookPtr);

    // Save Pointers for later
    This->FunctionPtr = (void *) FunctionPtr;
    This->HookPtr = HookPtr;

    if (Detour_Unprotect(__FUNCTION__, FunctionPtr, InstructionSize) < 0) return NULL;

    // Allocate Executable memory for stub and write instructions to stub and a jump back to original execution.
    This->StubSize = (InstructionSize + sizeof(This->JumpInstructions64));
    res = Detour_Alloc(This->StubSize, &This->StubPtr);
    if (res < 0 || This->StubPtr == 0) {
        klog("[Detour] %s: sceKernelMmap failed (0x%x).\n", __FUNCTION__, res);
        return 0;
    }

    memcpy(This->StubPtr, (void *) FunctionPtr, InstructionSize);
    Detour_WriteJump64(This, (void *) ((uint64_t) This->StubPtr + InstructionSize), (uint64_t)(FunctionPtr + InstructionSize));

    // Write jump from function to hook.
    memset((void *) FunctionPtr, 0x90, InstructionSize);
    Detour_WriteJump64(This, (void *) FunctionPtr, (uint64_t) This->TrampolinePtr);

    return This->StubPtr;
}

void *Detour_DetourFunction32(Detour *This, uint64_t FunctionPtr, void *HookPtr) {
    size_t InstructionSize = Detour_GetInstructionSize(This, FunctionPtr, sizeof(This->JumpInstructions32));

    if (InstructionSize < sizeof(This->JumpInstructions32)) {
        klog("[Detour] %s: InstructionSize: %zu\n", __FUNCTION__, InstructionSize);
        klog("[Detour] %s: Hooking Requires a minimum of %d bytes to write jump!\n", __FUNCTION__, (int)sizeof(This->JumpInstructions64));
        return NULL;
    }

    int res = Detour_Alloc(sizeof(This->JumpInstructions64), &This->TrampolinePtr);
    if (res < 0 || This->TrampolinePtr == 0) {
        klog("[Detour] %s: sceKernelMmap failed (0x%x).\n", __FUNCTION__, res);
        return 0;
    }

    Detour_WriteJump64(This, This->TrampolinePtr, (uint64_t) HookPtr);

    // Save Pointers for later
    This->FunctionPtr = (void *)FunctionPtr;
    This->HookPtr = HookPtr;

    if (Detour_Unprotect(__FUNCTION__, FunctionPtr, InstructionSize) < 0) return NULL;

    // Allocate Executable memory for stub and write instructions to stub and a jump back to original execution.
    This->StubSize = (InstructionSize + sizeof(This->JumpInstructions64));
    res = Detour_Alloc(This->StubSize, &This->StubPtr);
    if (res < 0 || This->StubPtr == 0) {
        klog("[Detour] %s: sceKernelMmap failed (0x%x).\n", __FUNCTION__, res);
        return 0;
    }

    memcpy(This->StubPtr, (void *) FunctionPtr, InstructionSize);
    Detour_WriteJump64(This, (void *) ((uint64_t)This->StubPtr + InstructionSize), (uint64_t)(FunctionPtr + InstructionSize));

    // Write jump from function to hook.
    memset((void *) FunctionPtr, 0x90, InstructionSize);
    Detour_WriteJump32(This, (void *) FunctionPtr, (uint64_t) This->TrampolinePtr);

    return This->StubPtr;
}

void* Detour_DetourFunction16(Detour* This, uint64_t FunctionPtr, void* HookPtr) {
    size_t InstructionSize =
        Detour_GetInstructionSize(This, FunctionPtr, sizeof(This->JumpInstructions16));

    if (InstructionSize < sizeof(This->JumpInstructions16)) {
        klog("[Detour] %s: InstructionSize: %zu\n", __FUNCTION__, InstructionSize);
        klog("[Detour] %s: Hooking Requires a minimum of %d bytes to write jump!\n", __FUNCTION__,
             (int)sizeof(This->JumpInstructions16));
        return NULL;
    }

    if (Detour_Unprotect(__FUNCTION__, FunctionPtr - sizeof(This->JumpInstructions32),
                         sizeof(This->JumpInstructions32)) < 0) return NULL;

    for (int i = 1; i <= sizeof(This->JumpInstructions32); i++) {
        if (*(uint8_t*)(FunctionPtr - i) != 0x90) {
            klog("[Detour] %s: Hooking Requires a minimum of %d bytes before the function to write jump!\n", __FUNCTION__,
                 (int)sizeof(This->JumpInstructions32));
            return NULL;
        }
    }

    int res = Detour_Alloc(sizeof(This->JumpInstructions64), &This->TrampolinePtr);
    if (res != 0 || This->TrampolinePtr == 0) {
        klog("[Detour] %s: sceKernelMmap failed (0x%x).\n", __FUNCTION__, res);
        return 0;
    }

    Detour_WriteJump64(This, This->TrampolinePtr, (uint64_t)HookPtr);

    // Save Pointers for later
    This->FunctionPtr = (void*)FunctionPtr;
    This->HookPtr = HookPtr;

    if (Detour_Unprotect(__FUNCTION__, FunctionPtr - 5, InstructionSize + 5) < 0) return NULL;

    // Allocate Executable memory for stub and write instructions to stub and a jump back to original execution.
    This->StubSize = (InstructionSize + sizeof(This->JumpInstructions64));
    res = Detour_Alloc(This->StubSize, &This->StubPtr);
    if (res < 0 || This->StubPtr == 0) {
        klog("[Detour] %s: sceKernelMmap failed (0x%x).\n", __FUNCTION__, res);
        return 0;
    }

    memcpy(This->StubPtr, (void*)FunctionPtr, InstructionSize);
    Detour_WriteJump64(This, (void*)((uint64_t)This->StubPtr + InstructionSize),
                       (uint64_t)(FunctionPtr + InstructionSize));

    // write back jump
    memset((void*)FunctionPtr, 0x90, InstructionSize);
    Detour_WriteJump16(This, (void*)FunctionPtr);

    // Write jump from function to hook.
    Detour_WriteJump32(This, (void*)(FunctionPtr - 5), (uint64_t)This->TrampolinePtr);

    return This->StubPtr;
};

void Detour_RestoreFunction(Detour *This) {
    void* RestorePtr = 0;
    size_t RestoreSize = 0;
    uint64_t JmpAddress = 0;

    if (This->StubPtr) {
        switch (This->Mode) {
            case DetourMode_x16:
                RestorePtr = This->FunctionPtr;
                RestoreSize = This->StubSize - sizeof(This->JumpInstructions16);
                break;

            case DetourMode_x32:
                RestorePtr = This->FunctionPtr;
                RestoreSize = This->StubSize - sizeof(This->JumpInstructions32);
                break;
            
            case DetourMode_x64:
                JmpAddress = Detour_GetJumpAddress64(This, This->FunctionPtr);
                RestorePtr = (JmpAddress != (uint64_t)This->TrampolinePtr) ? This->TrampolinePtr : This->FunctionPtr;
                RestoreSize = This->StubSize - sizeof(This->JumpInstructions64);
                break;
        }

        if (RestorePtr != 0 && RestoreSize != 0) {
            Detour_Unprotect(__FUNCTION__, (uint64_t) RestorePtr, RestoreSize);
            memcpy((void *) RestorePtr, This->StubPtr, RestoreSize);

            klog("[Detour] %s: (%p) has been Restored Successfully!\n", __FUNCTION__, RestorePtr);        }
    }
}

void Detour_Construct(Detour *This, DetourMode Mode) {
    This->StubPtr = 0;
    This->StubSize = 0;
    This->FunctionPtr = 0;
    This->TrampolinePtr = 0;
    This->HookPtr = 0;
    uint8_t ji16[] = { 0xEB, 0xF9 };
    memcpy(This->JumpInstructions16, ji16, sizeof(ji16));
    uint8_t ji32[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    memcpy(This->JumpInstructions32, ji32, sizeof(ji32));
    uint8_t ji64[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    memcpy(This->JumpInstructions64, ji64, sizeof(ji64));
    This->Mode = Mode;
}

void Detour_Destroy(Detour *This) {
    Detour_RestoreFunction(This);
}
