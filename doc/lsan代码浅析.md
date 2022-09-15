## 1. 结构体的定义

对于业务分配的每一块内存,都有一个元数据来描述内存的状态.

```c
struct ChunkMetadata // 内存块的元数据
{
    u8 allocated : 8;  // Must be first.
    ChunkTag tag : 2;
    uptr requested_size : 54; // 申请的内存大小
    u32 stack_trace_id;
};
```

对于业务分配的每一块内存,都会带有一个标记`ChunkTag`,用于标记内存的状态.

```c
// Chunk tags.
enum ChunkTag {
  kDirectlyLeaked = 0,  // 直接内存泄露
  kIndirectlyLeaked = 1, // 间接内存泄露
  kReachable = 2, // 内存依然可以访问
  kIgnored = 3 // 不检查此块内存(被忽略)
};
```

## 2. 内存分配

每一次的分配,lasn都会做记录,最终都会调用到`Allocate`来记录下内存信息,stack为堆栈信息,size为内存块大小,alignment为对齐参数.

```c
 void *Allocate(const StackTrace &stack, uptr size, uptr alignment, bool cleared)
 {
     if (size == 0)
         size = 1;
     if (size > kMaxAllowedMallocSize)
     {
         Report("WARNING: LeakSanitizer failed to allocate %zu bytes\n", size);
         return nullptr;
     }
     void *p = allocator.Allocate(&cache, size, alignment, false); // 通过分配器分配内存
     // Do not rely on the allocator to clear the memory (it's slow).
     if (cleared && allocator.FromPrimary(p))
         memset(p, 0, size);
     RegisterAllocation(stack, p, size); // 记录内存信息
     if (&__sanitizer_malloc_hook) __sanitizer_malloc_hook(p, size);
     RunMallocHooks(p, size);
     return p;
 }
```

`RegisterAllocation`会将相关信息写入元数据.

```c
static void RegisterAllocation(const StackTrace &stack, void *p, uptr size)
{
    if (!p) return;
    ChunkMetadata *m = Metadata(p);
    CHECK(m);
    m->tag = DisabledInThisThread() ? kIgnored : kDirectlyLeaked;
    m->stack_trace_id = StackDepotPut(stack);
    m->requested_size = size;
    atomic_store(reinterpret_cast<atomic_uint8_t *>(m), 1, memory_order_relaxed);
}
```

asan自己实现了malloc来替换系统本来的malloc:

```c
INTERCEPTOR(void*, malloc, uptr size) {
  ENSURE_LSAN_INITED;
  GET_STACK_TRACE_MALLOC; // 获取堆栈信息
  return Allocate(stack, size, 1, kAlwaysClearMemory);
}
```

## 3. 内存泄露检查

lsan最终会调用到`__lsan_do_leak_check`来检查内存泄露,

```c
void __lsan_do_leak_check() 
{
  if (common_flags()->detect_leaks)
    __lsan::DoLeakCheck();
}
```

这个函数最终会调用到`CheckForLeasks`来检查泄露,也就是在这个函数之中,输出了内存泄露报告.

```c
static bool CheckForLeaks()
{
    if (&__lsan_is_turned_off && __lsan_is_turned_off())
        return false;
    EnsureMainThreadIDIsCorrect();
    CheckForLeaksParam param;
    param.success = false;
    LockThreadRegistry();
    LockAllocator();
    DoStopTheWorld(CheckForLeaksCallback, &param);
    UnlockAllocator();
    UnlockThreadRegistry();

    if (!param.success)
    {
        Report("LeakSanitizer has encountered a fatal error.\n");
        Report(
            "HINT: For debugging, try setting environment variable "
            "LSAN_OPTIONS=verbosity=1:log_threads=1\n");
        Report(
            "HINT: LeakSanitizer does not work under ptrace (strace, gdb, etc)\n");
        Die();
    }
    param.leak_report.ApplySuppressions();
    uptr unsuppressed_count = param.leak_report.UnsuppressedLeakCount();
    if (unsuppressed_count > 0)
    {
        Decorator d;
        Printf("\n"
               "================================================================="
               "\n");
        Printf("%s", d.Error());
        Report("ERROR: LeakSanitizer: detected memory leaks\n");
        Printf("%s", d.End());
        param.leak_report.ReportTopLeaks(flags()->max_leaks);
    }
    if (common_flags()->print_suppressions)
        PrintMatchedSuppressions();
    if (unsuppressed_count > 0)
    {
        param.leak_report.PrintSummary();
        return true;
    }
    return false;
}
```

我们来看一下其中最为核心的`CheckForLeaksCallback`,这个函数最为重要的函数是对内存块进行分类``

```c
static void ClassifyAllChunks(SuspendedThreadsList const &suspended_threads)
{
    // Holds the flood fill frontier.
    Frontier frontier(1); // 创建一个容器

    ForEachChunk(CollectIgnoredCb, &frontier); // 遍历分配器分配出来的每一个内存块(chunk)
    ProcessGlobalRegions(&frontier);
    ProcessThreads(suspended_threads, &frontier);
    ProcessRootRegions(&frontier);
    FloodFillTag(&frontier, kReachable);

    // The check here is relatively expensive, so we do this in a separate flood
    // fill. That way we can skip the check for chunks that are reachable
    // otherwise.
    LOG_POINTERS("Processing platform-specific allocations.\n");
    CHECK_EQ(0, frontier.size());
    ProcessPlatformSpecificAllocations(&frontier);
    FloodFillTag(&frontier, kReachable);

    // Iterate over leaked chunks and mark those that are reachable from other
    // leaked chunks.
    LOG_POINTERS("Scanning leaked chunks.\n");
    ForEachChunk(MarkIndirectlyLeakedCb, nullptr);
}
```

第一步,

```c
static void CollectIgnoredCb(uptr chunk, void *arg)
{
    CHECK(arg);
    chunk = GetUserBegin(chunk);
    LsanMetadata m(chunk); // 通过chunk找到元数据
    if (m.allocated() && m.tag() == kIgnored)
    {
        // 将所有ignored的内存块加入frontier
        LOG_POINTERS("Ignored: chunk %p-%p of size %zu.\n",
                     chunk, chunk + m.requested_size(), m.requested_size());
        reinterpret_cast<Frontier *>(arg)->push_back(chunk);
    }
}
```

第2步,扫描全局变量中的指针:

```c
static int ProcessGlobalRegionsCallback(struct dl_phdr_info *info, size_t size,
                                            void *data)
{
    Frontier *frontier = reinterpret_cast<Frontier *>(data);
    for (uptr j = 0; j < info->dlpi_phnum; j++)
    {
        const ElfW(Phdr) *phdr = &(info->dlpi_phdr[j]);
        // We're looking for .data and .bss sections, which reside in writeable,
        // loadable segments.
        if (!(phdr->p_flags & PF_W) || (phdr->p_type != PT_LOAD) ||
            (phdr->p_memsz == 0))
            continue;
        // 查找.data以及.bss节,全局变量就存储在这里面
        uptr begin = info->dlpi_addr + phdr->p_vaddr;
        uptr end = begin + phdr->p_memsz; // 获得变量的起始位置
        uptr allocator_begin = 0, allocator_end = 0;
        GetAllocatorGlobalRange(&allocator_begin, &allocator_end);
        if (begin <= allocator_begin && allocator_begin < end)
        {
            if (begin < allocator_begin)
                ScanRangeForPointers(begin, allocator_begin, frontier, "GLOBAL",
                                     kReachable);
            if (allocator_end < end)
                ScanRangeForPointers(allocator_end, end, frontier, "GLOBAL",
                                     kReachable);
        }
        else
        {
            ScanRangeForPointers(begin, end, frontier, "GLOBAL", kReachable);
        }
    }
    return 0;
}

void ProcessGlobalRegions(Frontier *frontier)
{
    if (!flags()->use_globals) return;
    dl_iterate_phdr(ProcessGlobalRegionsCallback, frontier);
}
```

`ScanRangeForPointers`是核心函数,

```c
// Scans the memory range, looking for byte patterns that point into allocator
// chunks. Marks those chunks with |tag| and adds them to |frontier|.
// There are two usage modes for this function: finding reachable chunks
// (|tag| = kReachable) and finding indirectly leaked chunks
// (|tag| = kIndirectlyLeaked). In the second case, there's no flood fill,
// so |frontier| = 0.
void ScanRangeForPointers(uptr begin, uptr end,
                          Frontier *frontier,
                          const char *region_type, ChunkTag tag)
{
    CHECK(tag == kReachable || tag == kIndirectlyLeaked);
    const uptr alignment = flags()->pointer_alignment();
    LOG_POINTERS("Scanning %s range %p-%p.\n", region_type, begin, end);
    uptr pp = begin;
    if (pp % alignment)
        pp = pp + alignment - pp % alignment;
    for (; pp + sizeof(void *) <= end; pp += alignment)    // 每次移动一个指针的位置
    {
        void *p = *reinterpret_cast<void **>(pp); // 获得pp指针指向的值,强制转换为指针类型
        if (!CanBeAHeapPointer(reinterpret_cast<uptr>(p))) continue;
        uptr chunk = PointsIntoChunk(p); // 通过指针获得它所属的chunk
        if (!chunk) continue;
        // Pointers to self don't count. This matters when tag == kIndirectlyLeaked.
        if (chunk == begin) continue;
        LsanMetadata m(chunk); // 获得chunk的元数据
        if (m.tag() == kReachable || m.tag() == kIgnored) continue;

        // Do this check relatively late so we can log only the interesting cases.
        if (!flags()->use_poisoned && WordIsPoisoned(pp))
        {
            LOG_POINTERS(
                "%p is poisoned: ignoring %p pointing into chunk %p-%p of size "
                "%zu.\n",
                pp, p, chunk, chunk + m.requested_size(), m.requested_size());
            continue;
        }

        m.set_tag(tag); // 因为有指针引用这块内存,所以这块内存为tag(kReachable)
        LOG_POINTERS("%p: found %p pointing into chunk %p-%p of size %zu.\n", pp, p,
                     chunk, chunk + m.requested_size(), m.requested_size());
        if (frontier)
            frontier->push_back(chunk); // 将内存块对应的chunk加入frontier
    }
}
```

第3步,遍历`frontier`中的每一个内存块,将它们全部解释为指针,如果内存块A可以通过这些指针访问到,说明A是可达的,并非泄露.注意下面的while循环,它会将所有可以到达的内存块,都打上`kReachable`的标记.

```c
static void FloodFillTag(Frontier *frontier, ChunkTag tag)
{
    while (frontier->size())
    {
        uptr next_chunk = frontier->back();
        frontier->pop_back();
        LsanMetadata m(next_chunk);
        ScanRangeForPointers(next_chunk, next_chunk + m.requested_size(), frontier, "HEAP", tag);
    }
}
```

