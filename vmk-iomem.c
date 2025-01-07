#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define PAGE_SIZE 0x1000ULL // 4KB page size
#define CHUNK_SIZE 0x200000ULL // 2MB per chunk
#define HEADER_SIGNATURE "-FVE-FS-" // Header to search for
#define VMK_PATTERN "\x03\x20\x01\x00" // VMK pattern to search for
#define VMK_PATTERN_LEN 4 // Length of the VMK pattern

static unsigned long long get_physical_memory_size(void) {
    struct sysinfo si;
    si_meminfo(&si);
    return (unsigned long long)si.totalram * si.mem_unit;
}

static void *search_memory(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size) {
    const char *haystack_bytes = (const char *)haystack;
    for (size_t i = 0; i <= haystack_size - needle_size; ++i) {
        if (memcmp(haystack_bytes + i, needle, needle_size) == 0) {
            return (void *)(haystack_bytes + i);
        }
    }
    return NULL;
}

static int __init memory_scanner_init(void) {
    unsigned long long physical_mem_size = get_physical_memory_size();
    pr_info("[+] Detected physical memory size: %llu bytes\n", physical_mem_size);

    for (unsigned long long i = 0; i < (physical_mem_size / CHUNK_SIZE); i++) {
        unsigned long long chunk_base = i * CHUNK_SIZE;

        void __iomem *mapped_chunk = ioremap(chunk_base, CHUNK_SIZE);
        if (!mapped_chunk) {
            pr_err("[-] Failed to map physical memory at %llx\n", chunk_base);
            continue;
        }

        void *header_addr = search_memory(mapped_chunk, CHUNK_SIZE, HEADER_SIGNATURE, strlen(HEADER_SIGNATURE));
        if (!header_addr) {
            iounmap(mapped_chunk);
            continue;
        }

        pr_info("[+] Found header at address: %p\n", header_addr);

        uint32_t version = *(uint32_t *)(header_addr + 8 + 4);
        uint32_t start = *(uint32_t *)(header_addr + 8 + 4 + 4);
        uint32_t end = *(uint32_t *)(header_addr + 8 + 4 + 4 + 4);

        if (version != 1 || end <= start) {
            pr_warn("[!] Invalid version or size. Skipping...\n");
            iounmap(mapped_chunk);
            continue;
        }

        void *vmk_addr = search_memory(header_addr, end, VMK_PATTERN, VMK_PATTERN_LEN);
        if (!vmk_addr) {
            pr_warn("[!] VMK pattern not found.\n");
            iounmap(mapped_chunk);
            continue;
        }

        pr_info("[+] Found VMK pattern at address: %p\n", vmk_addr);
        iounmap(mapped_chunk);
    }

    return 0;
}

static void __exit memory_scanner_exit(void) {
    pr_info("[+] Memory scanner module unloaded.\n");
}

module_init(memory_scanner_init);
module_exit(memory_scanner_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Physical memory scanner");
