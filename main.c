#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <windows.h>

#include <psapi.h>
#include <process.h>

bool get_section_by_name(char const *string, IMAGE_SECTION_HEADER *section_hdr);
void __cdecl watch_thread(void *arg);

struct memory_range_t {
    uintptr_t base_address;
    size_t size;
};

typedef struct memory_range_t memory_range_t;

struct thread_params_t {
    memory_range_t memory_range;
    HANDLE wait_evt;
    HANDLE process;
};

typedef struct thread_params_t thread_params_t;

const uint16_t dos_magic = ('M' | 'Z' << 8);
const uint32_t pe_magic = ('P' | 'E' << 8);

const uint32_t max_elapsed = 10 * 1000;

int main() {
    printf("QueryWorkingSet Example\n");

    IMAGE_SECTION_HEADER text_section = { 0 };
    bool found = get_section_by_name(".text", &text_section);

    if (found != true) {
        printf("Failed to find .text section");
        return -1;
    }

    memory_range_t memory_range = {
        .base_address = (uintptr_t)((uintptr_t)GetModuleHandle(NULL) + text_section.VirtualAddress),
        .size = text_section.Misc.VirtualSize
    };

    HANDLE wait_evt = CreateEvent(NULL, TRUE, FALSE, NULL);

    thread_params_t params = {
        .memory_range = memory_range,
        .wait_evt = wait_evt,
        .process = GetCurrentProcess()
    };

    _beginthread(watch_thread, 0, (void *)&params);

    Sleep(1000);

    WaitForSingleObject(params.wait_evt, INFINITE);

    return 0;
}

bool get_section_by_name(char const *string, IMAGE_SECTION_HEADER *section_hdr) {
    bool ret = false;

    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
    if (dos_hdr != NULL) {
        if (dos_hdr->e_magic == dos_magic) {
            PIMAGE_NT_HEADERS nt_hdrs = (PIMAGE_NT_HEADERS)((uintptr_t)dos_hdr + dos_hdr->e_lfanew);
            if (nt_hdrs != NULL) {
                if (nt_hdrs->Signature == pe_magic) {
                    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)(
                            (uintptr_t)nt_hdrs
                            + sizeof(uint32_t)
                            + sizeof(IMAGE_FILE_HEADER)
                            + nt_hdrs->FileHeader.SizeOfOptionalHeader);
                    uint32_t n_sections = nt_hdrs->FileHeader.NumberOfSections;

                    for (int i = 0; i < n_sections; i++) {
                        IMAGE_SECTION_HEADER section = sections[i];
                        if (strcmp((char const *)section.Name, string) == 0) {
                            *section_hdr = section;
                            ret = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    return ret;
}

void __cdecl watch_thread(void *arg) {
    thread_params_t* params = (thread_params_t *)arg;
    PPSAPI_WORKING_SET_INFORMATION pwsi = NULL;
    uint32_t start = GetTickCount();

    pwsi = malloc(sizeof(PSAPI_WORKING_SET_INFORMATION));

    bool polling = true;
    while (polling) {
        bool ret = QueryWorkingSet(
                params->process,
                (PVOID)pwsi,
                sizeof(PSAPI_WORKING_SET_INFORMATION)
            );

        if (!ret && GetLastError() == ERROR_BAD_LENGTH) {
            uint32_t n_entries = pwsi->NumberOfEntries;
            free(pwsi);
            pwsi = malloc(sizeof(PSAPI_WORKING_SET_BLOCK) * n_entries + sizeof(pwsi->NumberOfEntries));
            QueryWorkingSet(
                    params->process,
                    (PVOID)pwsi,
                    sizeof(PSAPI_WORKING_SET_BLOCK) * n_entries + sizeof(pwsi->NumberOfEntries)
                );
        }

        for (int i = 0; i < pwsi->NumberOfEntries; i++) {
            PSAPI_WORKING_SET_BLOCK wsb = pwsi->WorkingSetInfo[i];
            uintptr_t page_range_start = params->memory_range.base_address / 0x1000;
            uintptr_t page_range_end = ((params->memory_range.base_address + params->memory_range.size) + 0xfff) / 0x1000;
            if (page_range_start <= wsb.VirtualPage && wsb.VirtualPage <= page_range_end) {
                if (wsb.Shared == 0) {
                    printf("Tamper detected in memory range %p - %p (Page VA %p, ShareCount %d)\n", (void *)params->memory_range.base_address, (void *)(params->memory_range.base_address + params->memory_range.size), (void *)(wsb.VirtualPage * 0x1000), wsb.ShareCount);
                    polling = false;
                    break;
                }
            }
        }

        if (polling) {
            uint32_t now = GetTickCount();
            if (now - start > max_elapsed) {
                printf("Timer elapsed, no tamper :)");
                break;
            }

            Sleep(500);
        }
    }

    free(pwsi);
    SetEvent(params->wait_evt);
}
