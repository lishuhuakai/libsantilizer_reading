//===-- asan_stack.cc -----------------------------------------------------===//
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Code for ASan stack trace.
//===----------------------------------------------------------------------===//
#include "asan_internal.h"
#include "asan_stack.h"
#include "sanitizer_common/sanitizer_atomic.h"
/* 堆栈回溯 */

namespace __asan
{

    static atomic_uint32_t malloc_context_size;
    /* 设置堆栈层数 */
    void SetMallocContextSize(u32 size)
    {
        atomic_store(&malloc_context_size, size, memory_order_release);
    }
    /* 堆栈层数限制 */
    u32 GetMallocContextSize()
    {
        return atomic_load(&malloc_context_size, memory_order_acquire);
    }

}  // namespace __asan

// ------------------ Interface -------------- {{{1

extern "C" {
    SANITIZER_INTERFACE_ATTRIBUTE
    void __sanitizer_print_stack_trace()
    {
        using namespace __asan;
        PRINT_CURRENT_STACK();
    }
}  // extern "C"
