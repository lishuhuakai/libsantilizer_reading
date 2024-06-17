## 1. 结构体定义

`asan` 分配的内存块的格式如下:

```c
// asan_allocator.cc
// 通过以下的内存分配器分配的内存块(memory chunk)格式如下:
// L L L L L L H H U U U U U U R R
//   L -- left redzone words (0 or more bytes)
//   H -- ChunkHeader (16 bytes), which is also a part of the left redzone.
//   U -- user memory.
//   R -- right redzone (0 or more bytes)
// ChunkBase consists of ChunkHeader and other bytes that overlap with user
// memory.

// If the left redzone is greater than the ChunkHeader size we store a magic
// value in the first uptr word of the memory block and store the address of
// ChunkBase in the next uptr.
// M B L L L L L L L L L  H H U U U U U U
//   |                    ^
//   ---------------------|
//   M -- magic value kAllocBegMagic
//   B -- address of ChunkHeader pointing to the first 'H'
static const uptr kAllocBegMagic = 0xCC6E96B9;

struct ChunkHeader
{
    // 1-st 8 bytes.
    u32 chunk_state       : 8;  // Must be first. chunk的状态
    u32 alloc_tid         : 24;

    u32 free_tid          : 24;
    u32 from_memalign     : 1;
    u32 alloc_type        : 2; // 内存的分配方式,比如通过malloc,通过new等.
    u32 rz_log            : 3;
    u32 lsan_tag          : 2;
    // 2-nd 8 bytes
    // This field is used for small sizes. For large sizes it is equal to
    // SizeClassMap::kMaxSize and the actual size is stored in the
    // SecondaryAllocator's metadata.
    u32 user_requested_size;
    u32 alloc_context_id;
};

struct ChunkBase : ChunkHeader
{
    // Header2, intersects with user memory. 第二头部
    u32 free_context_id;
};
static const uptr kChunkHeaderSize = sizeof(ChunkHeader); // 头部大小
static const uptr kChunkHeader2Size = sizeof(ChunkBase) - kChunkHeaderSize; // 第二头部大小
// 通过这个分配器分配的内存会处于以下三种状态之一:
// CHUNK_AVAILABLE: 内存块在空闲链表之中,可以用于分配
// CHUNK_ALLOCATED: 内存块已经被分配了,还没有被释放
// CHUNK_QUARANTINE: 内存块已经释放了,而且放入了隔离区
enum
{
    CHUNK_AVAILABLE  = 0,  // 0 is the default value even if we didn't set it.
    CHUNK_ALLOCATED  = 2,
    CHUNK_QUARANTINE = 3
};

struct AsanChunk: ChunkBase
{
    uptr Beg() // 内存块的开始位置
    {
        return reinterpret_cast<uptr>(this) + kChunkHeaderSize;
    }
    uptr UsedSize(bool locked_version = false)
    {
        if (user_requested_size != SizeClassMap::kMaxSize)
            return user_requested_size;
        return *reinterpret_cast<uptr *>(get_allocator().GetMetaData(AllocBeg(locked_version)));
    }
    void *AllocBeg(bool locked_version = false)
    {
        if (from_memalign)
        {
            if (locked_version)
                return get_allocator().GetBlockBeginFastLocked(reinterpret_cast<void *>(this));
            return get_allocator().GetBlockBegin(reinterpret_cast<void *>(this));
        }
        return reinterpret_cast<void*>(Beg() - RZLog2Size(rz_log));
    }
    bool AddrIsInside(uptr addr, bool locked_version = false) // 地址是否位于chunk之内
    {
        return (addr >= Beg()) && (addr < Beg() + UsedSize(locked_version));
    }
};
```

下文之中,我们会以`aarch64` 架构为例, 简要分析一下 `asan` 的实现逻辑, 下面是一些定义:

```c
// asan_allocator.h
typedef SizeClassMap<3, 4, 8, 17, 128, 16> DefaultSizeClassMap;

// AArch64/SANITIZER_CAN_USER_ALLOCATOR64 is only for 42-bit VMA
// so no need to different values for different VMA.
const uptr kAllocatorSpace =  0x10000000000ULL;
const uptr kAllocatorSize  =  0x10000000000ULL;  // 3T.
typedef DefaultSizeClassMap SizeClassMap;

// 分配器参数
struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
  static const uptr kSpaceBeg = kAllocatorSpace; // 起始地址
  static const uptr kSpaceSize = kAllocatorSize; // 大小
  static const uptr kMetadataSize = 0;
  typedef __asan::SizeClassMap SizeClassMap;
  typedef AsanMapUnmapCallback MapUnmapCallback;
  static const uptr kFlags = 0;
};

// map以及unmap函数,asan主要通过这两个函数向操作系统申请/释放内存
struct AsanMapUnmapCallback {
    void OnMap(uptr p, uptr size) const;
    void OnUnmap(uptr p, uptr size) const;
};

typedef SizeClassAllocator64<AP64> PrimaryAllocator; // 第一分配器,分配小内存
static const uptr kNumberOfSizeClasses = SizeClassMap::kNumClasses; // sizeclass的个数
typedef SizeClassAllocatorLocalCache<PrimaryAllocator> AllocatorCache; // 缓存,加快内存分配速度
typedef LargeMmapAllocator<AsanMapUnmapCallback> SecondaryAllocator; // 第二分配器,用于分配大内存
typedef CombinedAllocator<PrimaryAllocator, AllocatorCache, SecondaryAllocator> AsanAllocator; // asan内存分配器
```

`asan` 的分配器定义如下:

```c
// asan_allocator.cc
struct Allocator // 分配器
{
    static const uptr kMaxAllowedMallocSize = FIRST_32_SECOND_64(3UL << 30, 1ULL << 40);
    static const uptr kMaxThreadLocalQuarantine = FIRST_32_SECOND_64(1 << 18, 1 << 20);

    AsanAllocator allocator;    // ASAN内存分配器
    AsanQuarantine quarantine;  // 隔离区
    StaticSpinMutex fallback_mutex;
    AllocatorCache fallback_allocator_cache;
    QuarantineCache fallback_quarantine_cache;

    // ------------------- Options --------------------------
    atomic_uint16_t min_redzone;
    atomic_uint16_t max_redzone;
    atomic_uint8_t alloc_dealloc_mismatch;
    // ------------------- Initialization ------------------------
    // ....
}
```

全局有且仅有一个静态的内存分配器:

```c
// asan_allocator.cc
static Allocator instance(LINKER_INITIALIZED);

static AsanAllocator &get_allocator()
{
    return instance.allocator; // 全局asan分配器
}
```

接下来,我们会逐一来解析一下这些定义之中一些非常重要的结构体.

### 1.1 sizeclass Map

上层应用申请的内存的大小可能是任意的,上层应用申请多大,就实际分配多大一块内存这种内存分配策略并不利于 `asan` 的内存管理,而且容易造成较多的内存碎片,不方便内存的复用.

`asan` 根据内存块的大小,对内存块进行了分类,一共有 `n` 类( `n` 为 `kNumClasses` ),每一个类别都是一个 `sizeclass` ,每一类都对应一个内存区间:

|    内存区间    |  sizeclass   |
| :------------: | :----------: |
|   (0, x~1~]    | sizeclass~1~ |
|  (x~1~, x~2~]  | sizeclass~2~ |
|      ...       |     ...      |
| (x~n-1~, x~n~] | sizeclass~n~ |

其中 x~1~ < ... < x~n~,上层应用申请的内存块大小size如果落在sizeclass~i~的内存区间之内,asan实际会返回一块大小为x~i~的空闲内存块.

在实际的环境中,sizeclass的类别数可能会达到52甚至于更高.

为了实现size <-> sizeclass的相互转换,定义了`SizeClassMap`这样一个模板类.

```c
// asan_allocator.h
// SizeClassMap maps allocation sizes into size classes and back.
// Class 0 always corresponds to size 0.
// The other sizes are controlled by the template parameters:
// 
//   kMinSizeLog: defines the class 1    as 2^kMinSizeLog.
//   kMaxSizeLog: defines the last class as 2^kMaxSizeLog.
//   kMidSizeLog: the classes starting from 1 increase with step
//                2^kMinSizeLog until 2^kMidSizeLog.
//   kNumBits: the number of non-zero bits in sizes after 2^kMidSizeLog.
//             E.g. with kNumBits==3 all size classes after 2^kMidSizeLog
//             look like 0b1xx0..0, where x is either 0 or 1.
//
// Example: kNumBits=3, kMidSizeLog=4, kMidSizeLog=8, kMaxSizeLog=17:
//
// Classes 1 - 16 correspond to sizes 16 to 256 (size = class_id * 16).
// Next 4 classes: 256 + i * 64  (i = 1 to 4).
// Next 4 classes: 512 + i * 128 (i = 1 to 4).
// ...
// Next 4 classes: 2^k + i * 2^(k-2) (i = 1 to 4).
// Last class corresponds to kMaxSize = 1 << kMaxSizeLog.
//
// This structure of the size class map gives us:
//   - Efficient table-free class-to-size and size-to-class functions.
//   - Difference between two consequent size classes is between 14% and 25%
//
// This class also gives a hint to a thread-caching allocator about the amount
// of chunks that need to be cached per-thread:
//  - kMaxNumCachedHint is a hint for maximal number of chunks per size class.
//    The actual number is computed in TransferBatch.
//  - (1 << kMaxBytesCachedLog) is the maximal number of bytes per size class.
//
// Part of output of SizeClassMap::Print():
// c00 => s: 0 diff: +0 00% l 0 cached: 0 0; id 0
// c01 => s: 16 diff: +16 00% l 4 cached: 256 4096; id 1
// c02 => s: 32 diff: +16 100% l 5 cached: 256 8192; id 2
// c03 => s: 48 diff: +16 50% l 5 cached: 256 12288; id 3
// c04 => s: 64 diff: +16 33% l 6 cached: 256 16384; id 4
// c05 => s: 80 diff: +16 25% l 6 cached: 256 20480; id 5
// c06 => s: 96 diff: +16 20% l 6 cached: 256 24576; id 6
// c07 => s: 112 diff: +16 16% l 6 cached: 256 28672; id 7
//
// c08 => s: 128 diff: +16 14% l 7 cached: 256 32768; id 8
// c09 => s: 144 diff: +16 12% l 7 cached: 256 36864; id 9
// c10 => s: 160 diff: +16 11% l 7 cached: 256 40960; id 10
// c11 => s: 176 diff: +16 10% l 7 cached: 256 45056; id 11
// c12 => s: 192 diff: +16 09% l 7 cached: 256 49152; id 12
// c13 => s: 208 diff: +16 08% l 7 cached: 256 53248; id 13
// c14 => s: 224 diff: +16 07% l 7 cached: 256 57344; id 14
// c15 => s: 240 diff: +16 07% l 7 cached: 256 61440; id 15
//
// c16 => s: 256 diff: +16 06% l 8 cached: 256 65536; id 16
// c17 => s: 320 diff: +64 25% l 8 cached: 204 65280; id 17
// c18 => s: 384 diff: +64 20% l 8 cached: 170 65280; id 18
// c19 => s: 448 diff: +64 16% l 8 cached: 146 65408; id 19
//
// c20 => s: 512 diff: +64 14% l 9 cached: 128 65536; id 20
// c21 => s: 640 diff: +128 25% l 9 cached: 102 65280; id 21
// c22 => s: 768 diff: +128 20% l 9 cached: 85 65280; id 22
// c23 => s: 896 diff: +128 16% l 9 cached: 73 65408; id 23
//
// c24 => s: 1024 diff: +128 14% l 10 cached: 64 65536; id 24
// c25 => s: 1280 diff: +256 25% l 10 cached: 51 65280; id 25
// c26 => s: 1536 diff: +256 20% l 10 cached: 42 64512; id 26
// c27 => s: 1792 diff: +256 16% l 10 cached: 36 64512; id 27
//
// ...
//
// c48 => s: 65536 diff: +8192 14% l 16 cached: 1 65536; id 48
// c49 => s: 81920 diff: +16384 25% l 16 cached: 1 81920; id 49
// c50 => s: 98304 diff: +16384 20% l 16 cached: 1 98304; id 50
// c51 => s: 114688 diff: +16384 16% l 16 cached: 1 114688; id 51
//
// c52 => s: 131072 diff: +16384 14% l 17 cached: 1 131072; id 52
//
//
// Another example (kNumBits=2):
// c00 => s: 0 diff: +0 00% l 0 cached: 0 0; id 0
// c01 => s: 32 diff: +32 00% l 5 cached: 64 2048; id 1
// c02 => s: 64 diff: +32 100% l 6 cached: 64 4096; id 2
// c03 => s: 96 diff: +32 50% l 6 cached: 64 6144; id 3
// c04 => s: 128 diff: +32 33% l 7 cached: 64 8192; id 4
// c05 => s: 160 diff: +32 25% l 7 cached: 64 10240; id 5
// c06 => s: 192 diff: +32 20% l 7 cached: 64 12288; id 6
// c07 => s: 224 diff: +32 16% l 7 cached: 64 14336; id 7
// c08 => s: 256 diff: +32 14% l 8 cached: 64 16384; id 8
// c09 => s: 384 diff: +128 50% l 8 cached: 42 16128; id 9
// c10 => s: 512 diff: +128 33% l 9 cached: 32 16384; id 10
// c11 => s: 768 diff: +256 50% l 9 cached: 21 16128; id 11
// c12 => s: 1024 diff: +256 33% l 10 cached: 16 16384; id 12
// c13 => s: 1536 diff: +512 50% l 10 cached: 10 15360; id 13
// c14 => s: 2048 diff: +512 33% l 11 cached: 8 16384; id 14
// c15 => s: 3072 diff: +1024 50% l 11 cached: 5 15360; id 15
// c16 => s: 4096 diff: +1024 33% l 12 cached: 4 16384; id 16
// c17 => s: 6144 diff: +2048 50% l 12 cached: 2 12288; id 17
// c18 => s: 8192 diff: +2048 33% l 13 cached: 2 16384; id 18
// c19 => s: 12288 diff: +4096 50% l 13 cached: 1 12288; id 19
// c20 => s: 16384 diff: +4096 33% l 14 cached: 1 16384; id 20
// c21 => s: 24576 diff: +8192 50% l 14 cached: 1 24576; id 21
// c22 => s: 32768 diff: +8192 33% l 15 cached: 1 32768; id 22
// c23 => s: 49152 diff: +16384 50% l 15 cached: 1 49152; id 23
// c24 => s: 65536 diff: +16384 33% l 16 cached: 1 65536; id 24
// c25 => s: 98304 diff: +32768 50% l 16 cached: 1 98304; id 25
// c26 => s: 131072 diff: +32768 33% l 17 cached: 1 131072; id 26
template <uptr kNumBits, uptr kMinSizeLog, uptr kMidSizeLog, uptr kMaxSizeLog,
          uptr kMaxNumCachedHintT, uptr kMaxBytesCachedLog>
class SizeClassMap
{
    static const uptr kMinSize = 1 << kMinSizeLog; // 最小的sizeclass的大小
    static const uptr kMidSize = 1 << kMidSizeLog;
    static const uptr kMidClass = kMidSize / kMinSize; // 中间class
    static const uptr S = kNumBits - 1;
    static const uptr M = (1 << S) - 1;

public:
    // kMaxNumCachedHintT is a power of two. It serves as a hint
    // for the size of TransferBatch, the actual size could be a bit smaller.
    static const uptr kMaxNumCachedHint = kMaxNumCachedHintT;
    COMPILER_CHECK((kMaxNumCachedHint & (kMaxNumCachedHint - 1)) == 0);

    static const uptr kMaxSize = 1UL << kMaxSizeLog;
    static const uptr kNumClasses =
        kMidClass + ((kMaxSizeLog - kMidSizeLog) << S) + 1; // sizeclass的个数
    static const uptr kLargestClassID = kNumClasses - 2;
    COMPILER_CHECK(kNumClasses >= 16 && kNumClasses <= 256);
    static const uptr kNumClassesRounded =
        kNumClasses <= 32  ? 32 :
        kNumClasses <= 64  ? 64 :
        kNumClasses <= 128 ? 128 : 256;

    static uptr Size(uptr class_id) // 获取类的大小的上限值
    {
        if (class_id <= kMidClass)
            return kMinSize * class_id; // 类别小于等于midclass,大小为kMinSize * class_id
        class_id -= kMidClass;
        uptr t = kMidSize << (class_id >> S);
        return t + (t >> S) * (class_id & M);
    }

    static uptr ClassID(uptr size) // 根据大小,获取其对应的class
    {
        if (size <= kMidSize)
            return (size + kMinSize - 1) >> kMinSizeLog;
        if (size > kMaxSize) return 0;
        uptr l = MostSignificantSetBitIndex(size);
        uptr hbits = (size >> (l - S)) & M;
        uptr lbits = size & ((1 << (l - S)) - 1);
        uptr l1 = l - kMidSizeLog;
        return kMidClass + (l1 << S) + hbits + (lbits > 0);
    }

    static uptr MaxCachedHint(uptr class_id)
    {
        if (class_id == 0) return 0;
        uptr n = (1UL << kMaxBytesCachedLog) / Size(class_id);
        return Max<uptr>(1, Min(kMaxNumCachedHint, n));
    }
	/* 打印出每一个SizeClass的内存分配信息 */
    static void Print()
    {
        uptr prev_s = 0;
        uptr total_cached = 0;
        for (uptr i = 0; i < kNumClasses; i++)
        {
            uptr s = Size(i);
            if (s >= kMidSize / 2 && (s & (s - 1)) == 0)
                Printf("\n");
            uptr d = s - prev_s;
            uptr p = prev_s ? (d * 100 / prev_s) : 0;
            uptr l = s ? MostSignificantSetBitIndex(s) : 0;
            uptr cached = MaxCachedHint(i) * s;
            Printf("c%02zd => s: %zd diff: +%zd %02zd%% l %zd "
                   "cached: %zd %zd; id %zd\n",
                   i, Size(i), d, p, l, MaxCachedHint(i), cached, ClassID(s));
            total_cached += cached;
            prev_s = s;
        }
        Printf("Total cached: %zd\n", total_cached);
    }
	// ...
};

typedef SizeClassMap<3, 4, 8, 17, 128, 16> DefaultSizeClassMap;
```

### 1.2 sizeclass Cache

`SizeClassAllocatorLocalCache` 其实就是一个缓存,用于存储每个级别的 `sizeclass` 的空闲内存块.

它向外提供了 `Allocator` 接口,用于内存分配.

```c
// Objects of this type should be used as local caches for SizeClassAllocator64
// or SizeClassAllocator32. Since the typical use of this class is to have one
// object per thread in TLS, is has to be POD.
template<class SizeClassAllocator>
struct SizeClassAllocatorLocalCache
    : SizeClassAllocator::AllocatorCache
{
};

// Cache used by SizeClassAllocator64.
template <class SizeClassAllocator>
struct SizeClassAllocator64LocalCache // 模板类
{
    typedef SizeClassAllocator Allocator; // sizeclass的内存分配器
    static const uptr kNumClasses = SizeClassAllocator::kNumClasses;
    typedef typename Allocator::SizeClassMapT SizeClassMap;
    typedef typename Allocator::CompactPtrT CompactPtrT;

    void Init(AllocatorGlobalStats *s)
    {
        stats_.Init();
        if (s)
            s->Register(&stats_);
    }

    void Destroy(SizeClassAllocator *allocator, AllocatorGlobalStats *s)
    {
        Drain(allocator);
        if (s)
            s->Unregister(&stats_);
    }
    /* 内存分配
     * @param class_id 内存大小级别
     */
    void *Allocate(SizeClassAllocator *allocator, uptr class_id);
    
    /* 内存释放
     * @param class_id 内存级别
     * @param p 内存首地址
     */
    void Deallocate(SizeClassAllocator *allocator, uptr class_id, void *p);

    void Drain(SizeClassAllocator *allocator)
    {
        for (uptr class_id = 0; class_id < kNumClasses; class_id++)
        {
            PerClass *c = &per_class_[class_id];
            while (c->count > 0)
                Drain(c, allocator, class_id, c->count);
        }
    }

    // private:
    struct PerClass
    {
        u32 count;
        u32 max_count;
        CompactPtrT chunks[2 * SizeClassMap::kMaxNumCachedHint];
    };
    PerClass per_class_[kNumClasses]; // 每一个级别的内存的相关信息
    AllocatorStats stats_; // 内存分配统计信息

    void InitCache()
    {
        if (per_class_[1].max_count)
            return;
        for (uptr i = 0; i < kNumClasses; i++)
        {
            PerClass *c = &per_class_[i];
            c->max_count = 2 * SizeClassMap::MaxCachedHint(i);
        }
    }
    // 重新申请内存
    void Refill(PerClass *c, SizeClassAllocator *allocator,
                         uptr class_id)
    {
        InitCache();
        uptr num_requested_chunks = SizeClassMap::MaxCachedHint(class_id);
        allocator->GetFromAllocator(&stats_, class_id, c->chunks,
                                    num_requested_chunks);
        c->count = num_requested_chunks;
    }

    void Drain(PerClass *c, SizeClassAllocator *allocator, uptr class_id,
                        uptr count)
    {
        InitCache();
        CHECK_GE(c->count, count);
        uptr first_idx_to_drain = c->count - count;
        c->count -= count;
        allocator->ReturnToAllocator(&stats_, class_id,
                                     &c->chunks[first_idx_to_drain], count);
    }
};
```

### 1.3 内存分配器

 `asan` 实际会将两个内存分配器组合起来使用, 一个 `PrimaryAllocatior` 用于分配小内存, 一个 `SecondaryAllocator` 用于分配大内存.

```cpp
// sanitizer_allocator_combined.h
// This class implements a complete memory allocator by using two
// internal allocators:
// PrimaryAllocator is efficient, but may not allocate some sizes (alignments).
//  When allocating 2^x bytes it should return 2^x aligned chunk.
// PrimaryAllocator is used via a local AllocatorCache.
// SecondaryAllocator can allocate anything, but is not efficient.
template <class PrimaryAllocator, class AllocatorCache,
          class SecondaryAllocator>  // NOLINT
class CombinedAllocator
{
public:
    void InitCommon(bool may_return_null)
    {
        primary_.Init();
        atomic_store(&may_return_null_, may_return_null, memory_order_relaxed);
    }

    void InitLinkerInitialized(bool may_return_null)
    {
        secondary_.InitLinkerInitialized(may_return_null);
        stats_.InitLinkerInitialized();
        InitCommon(may_return_null);
    }

    void Init(bool may_return_null)
    {
        secondary_.Init(may_return_null);
        stats_.Init();
        InitCommon(may_return_null);
    }
    /* 内存分配 */
    void *Allocate(AllocatorCache *cache, uptr size, uptr alignment,
                   bool cleared = false, bool check_rss_limit = false)
    {
        // Returning 0 on malloc(0) may break a lot of code.
        if (size == 0)
            size = 1;
        if (size + alignment < size) return ReturnNullOrDieOnBadRequest();
        if (check_rss_limit && RssLimitIsExceeded()) return ReturnNullOrDieOnOOM();
        if (alignment > 8)
            size = RoundUpTo(size, alignment);
        void *res;
        // 如果第一内存分配器可以分配, 就使用第一内存分配器来分配内存
        bool from_primary = primary_.CanAllocate(size, alignment);
        if (from_primary)
            res = cache->Allocate(&primary_, primary_.ClassID(size));
        else // 否则使用第二内存分配器来分配内存
            res = secondary_.Allocate(&stats_, size, alignment);
        if (alignment > 8)
            CHECK_EQ(reinterpret_cast<uptr>(res) & (alignment - 1), 0);
        if (cleared && res && from_primary)
            internal_bzero_aligned16(res, RoundUpTo(size, 16));
        return res;
    }

 	// ...
    
    /* 内存释放 */
    void Deallocate(AllocatorCache *cache, void *p)
    {
        if (!p) return;
        if (primary_.PointerIsMine(p))
            cache->Deallocate(&primary_, primary_.GetSizeClass(p), p);
        else
            secondary_.Deallocate(&stats_, p);
    }
    
	/* 内存重分配 */
    void *Reallocate(AllocatorCache *cache, void *p, uptr new_size,
                     uptr alignment)
    {
        if (!p)
            return Allocate(cache, new_size, alignment);
        if (!new_size)
        {
            Deallocate(cache, p);
            return nullptr;
        }
        CHECK(PointerIsMine(p));
        uptr old_size = GetActuallyAllocatedSize(p);
        uptr memcpy_size = Min(new_size, old_size);
        void *new_p = Allocate(cache, new_size, alignment);
        if (new_p)
            internal_memcpy(new_p, p, memcpy_size);
        Deallocate(cache, p);
        return new_p;
    }
	/* 判断内存是否由本内存分配器分配 */
    bool PointerIsMine(void *p)
    {
        if (primary_.PointerIsMine(p))
            return true;
        return secondary_.PointerIsMine(p);
    }

    bool FromPrimary(void *p)
    {
        return primary_.PointerIsMine(p);
    }

    void *GetBlockBegin(const void *p)
    {
        if (primary_.PointerIsMine(p))
            return primary_.GetBlockBegin(p);
        return secondary_.GetBlockBegin(p);
    }

    // This function does the same as GetBlockBegin, but is much faster.
    // Must be called with the allocator locked.
    void *GetBlockBeginFastLocked(void *p)
    {
        if (primary_.PointerIsMine(p))
            return primary_.GetBlockBegin(p);
        return secondary_.GetBlockBeginFastLocked(p);
    }

    uptr GetActuallyAllocatedSize(void *p)
    {
        if (primary_.PointerIsMine(p))
            return primary_.GetActuallyAllocatedSize(p);
        return secondary_.GetActuallyAllocatedSize(p);
    }

    uptr TotalMemoryUsed()
    {
        return primary_.TotalMemoryUsed() + secondary_.TotalMemoryUsed();
    }

    void InitCache(AllocatorCache *cache)
    {
        cache->Init(&stats_);
    }

    void DestroyCache(AllocatorCache *cache)
    {
        cache->Destroy(&primary_, &stats_);
    }

    void SwallowCache(AllocatorCache *cache)
    {
        cache->Drain(&primary_);
    }

    void GetStats(AllocatorStatCounters s) const
    {
        stats_.Get(s);
    }
	/* 打印统计信息 */
    void PrintStats()
    {
        primary_.PrintStats();
        secondary_.PrintStats();
    }

	/* 将内存返还给操作系统 */
    void ReleaseToOS()
    {
        primary_.ReleaseToOS();
    }

    // Iterate over all existing chunks.
    // The allocator must be locked when calling this function.
    void ForEachChunk(ForEachChunkCallback callback, void *arg)
    {
        primary_.ForEachChunk(callback, arg);
        secondary_.ForEachChunk(callback, arg);
    }

private:
    PrimaryAllocator primary_;
    SecondaryAllocator secondary_;
    AllocatorGlobalStats stats_;
    atomic_uint8_t may_return_null_;
    atomic_uint8_t rss_limit_is_exceeded_;
};
```
#### 1. 第一内存分配器

对于 `aarch64` 而言,`SizeClassAllocator64<AP64>`是其第一分配器,我们来看一下 `sizeClassAllocator64` 是如何来实现的吧.

```c
// sanitizer_allocator_primary64.h
/* 64位内存分配器 */
template <class Params>
class SizeClassAllocator64
{
public:
    static const uptr kSpaceBeg = Params::kSpaceBeg;
    static const uptr kSpaceSize = Params::kSpaceSize;
    static const uptr kMetadataSize = Params::kMetadataSize;
    typedef typename Params::SizeClassMap SizeClassMap;
    typedef typename Params::MapUnmapCallback MapUnmapCallback;

    static const bool kRandomShuffleChunks =
        Params::kFlags & SizeClassAllocator64FlagMasks::kRandomShuffleChunks;

    typedef SizeClassAllocator64<Params> ThisT;
    typedef SizeClassAllocator64LocalCache<ThisT> AllocatorCache; // 注意这里定义了sizeclass缓存

    // When we know the size class (the region base) we can represent a pointer
    // as a 4-byte integer (offset from the region start shifted right by 4).
    typedef u32 CompactPtrT;
    static const uptr kCompactPtrScale = 4;
    CompactPtrT PointerToCompactPtr(uptr base, uptr ptr) //将实际的指针转换为压缩指针(节约空间)
    {
        return static_cast<CompactPtrT>((ptr - base) >> kCompactPtrScale);
    }
    uptr CompactPtrToPointer(uptr base, CompactPtrT ptr32) // 将压缩指针转换为实际的指针
    {
        return base + (static_cast<uptr>(ptr32) << kCompactPtrScale);
    }

    void Init()
    {
        uptr TotalSpaceSize = kSpaceSize + AdditionalSize();
        if (kUsingConstantSpaceBeg)
        {
            CHECK_EQ(kSpaceBeg, reinterpret_cast<uptr>(
                         MmapFixedNoAccess(kSpaceBeg, TotalSpaceSize)));
        }
        else
        {
            NonConstSpaceBeg =
                reinterpret_cast<uptr>(MmapNoAccess(TotalSpaceSize));
            CHECK_NE(NonConstSpaceBeg, ~(uptr)0);
        }
        MapWithCallback(SpaceEnd(), AdditionalSize());
    }

    void MapWithCallback(uptr beg, uptr size) // 向操作系统申请内存
    {
        CHECK_EQ(beg, reinterpret_cast<uptr>(MmapFixedOrDie(beg, size)));
        MapUnmapCallback().OnMap(beg, size);
    }

    void UnmapWithCallback(uptr beg, uptr size) // 向操作系统返还内存
    {
        MapUnmapCallback().OnUnmap(beg, size);
        UnmapOrDie(reinterpret_cast<void *>(beg), size);
    }

    static bool CanAllocate(uptr size, uptr alignment) // 判断分配器是否能够分配size大小的内存
    {
        return size <= SizeClassMap::kMaxSize && alignment <= SizeClassMap::kMaxSize;
    }

    void ReturnToAllocator(AllocatorStats *stat, uptr class_id,
                                    const CompactPtrT *chunks, uptr n_chunks); // 将内存返还给分配器
  
    
    // 从分配器中获得内存块(大小为class_id对应的sizecalss的内存大小
    void GetFromAllocator(AllocatorStats *stat, uptr class_id, CompactPtrT *chunks, uptr n_chunks);
	// 内存是否由本分配器分配出去
    bool PointerIsMine(const void *p)
    {
        uptr P = reinterpret_cast<uptr>(p);
        if (kUsingConstantSpaceBeg && (kSpaceBeg % kSpaceSize) == 0)
            return P / kSpaceSize == kSpaceBeg / kSpaceSize;
        return P >= SpaceBeg() && P < SpaceEnd();
    }

    uptr GetRegionBegin(const void *p)
    {
        if (kUsingConstantSpaceBeg)
            return reinterpret_cast<uptr>(p) & ~(kRegionSize - 1);
        uptr space_beg = SpaceBeg();
        return ((reinterpret_cast<uptr>(p)  - space_beg) & ~(kRegionSize - 1)) + space_beg;
    }

    uptr GetRegionBeginBySizeClass(uptr class_id)
    {
        return SpaceBeg() + kRegionSize * class_id;
    }

    uptr GetSizeClass(const void *p)
    {
        if (kUsingConstantSpaceBeg && (kSpaceBeg % kSpaceSize) == 0)
            return ((reinterpret_cast<uptr>(p)) / kRegionSize) % kNumClassesRounded;
        return ((reinterpret_cast<uptr>(p) - SpaceBeg()) / kRegionSize) % kNumClassesRounded;
    }

    void *GetBlockBegin(const void *p)
    {
        uptr class_id = GetSizeClass(p);
        uptr size = ClassIdToSize(class_id);
        if (!size) return nullptr;
        uptr chunk_idx = GetChunkIdx((uptr)p, size);
        uptr reg_beg = GetRegionBegin(p);
        uptr beg = chunk_idx * size;
        uptr next_beg = beg + size;
        if (class_id >= kNumClasses) return nullptr;
        RegionInfo *region = GetRegionInfo(class_id);
        if (region->mapped_user >= next_beg)
            return reinterpret_cast<void*>(reg_beg + beg);
        return nullptr;
    }

    uptr GetActuallyAllocatedSize(void *p)
    {
        CHECK(PointerIsMine(p));
        return ClassIdToSize(GetSizeClass(p));
    }

    uptr ClassID(uptr size) // 根据内存大小(size),获得它所对应的sizeclass(其大小大于size同时最小)
    {
        return SizeClassMap::ClassID(size);
    }

    void *GetMetaData(const void *p)
    {
        uptr class_id = GetSizeClass(p);
        uptr size = ClassIdToSize(class_id);
        uptr chunk_idx = GetChunkIdx(reinterpret_cast<uptr>(p), size);
        uptr region_beg = GetRegionBeginBySizeClass(class_id);
        return reinterpret_cast<void *>(GetMetadataEnd(region_beg) -
                                        (1 + chunk_idx) * kMetadataSize);
    }

    uptr TotalMemoryUsed()
    {
        uptr res = 0;
        for (uptr i = 0; i < kNumClasses; i++)
            res += GetRegionInfo(i)->allocated_user;
        return res;
    }

    static void FillMemoryProfile(uptr start, uptr rss, bool file, uptr *stats,
                                  uptr stats_size)
    {
        for (uptr class_id = 0; class_id < stats_size; class_id++)
            if (stats[class_id] == start)
                stats[class_id] = rss;
    }
	// 打印每一个sizeclass的统计信息
    void PrintStats(uptr class_id, uptr rss);

    void PrintStats()
    {
        uptr total_mapped = 0;
        uptr n_allocated = 0;
        uptr n_freed = 0;
        for (uptr class_id = 1; class_id < kNumClasses; class_id++)
        {
            RegionInfo *region = GetRegionInfo(class_id);
            total_mapped += region->mapped_user;
            n_allocated += region->n_allocated;
            n_freed += region->n_freed; // 空闲内存
        }
        Printf("Stats: SizeClassAllocator64: %zdM mapped in %zd allocations; "
               "remains %zd\n",
               total_mapped >> 20, n_allocated, n_allocated - n_freed);
        uptr rss_stats[kNumClasses];
        for (uptr class_id = 0; class_id < kNumClasses; class_id++)
            rss_stats[class_id] = SpaceBeg() + kRegionSize * class_id;
        GetMemoryProfile(FillMemoryProfile, rss_stats, kNumClasses);
        for (uptr class_id = 1; class_id < kNumClasses; class_id++)
            PrintStats(class_id, rss_stats[class_id]);
    }
    // Iterate over all existing chunks.
    // The allocator must be locked when calling this function.
    void ForEachChunk(ForEachChunkCallback callback, void *arg)
    {
        for (uptr class_id = 1; class_id < kNumClasses; class_id++)
        {
            RegionInfo *region = GetRegionInfo(class_id);
            uptr chunk_size = ClassIdToSize(class_id);
            uptr region_beg = SpaceBeg() + class_id * kRegionSize;
            for (uptr chunk = region_beg;
                 chunk < region_beg + region->allocated_user;
                 chunk += chunk_size)
            {
                // Too slow: CHECK_EQ((void *)chunk, GetBlockBegin((void *)chunk));
                callback(chunk, arg);
            }
        }
    }

    static uptr ClassIdToSize(uptr class_id) // 获取class_id对应的sizeclass的大小
    {
        return SizeClassMap::Size(class_id);
    }

    static uptr AdditionalSize()
    {
        return RoundUpTo(sizeof(RegionInfo) * kNumClassesRounded,
                         GetPageSizeCached());
    }
	// 将内存返还给操作系统
    void ReleaseToOS()
    {
        for (uptr class_id = 1; class_id < kNumClasses; class_id++)
            ReleaseToOS(class_id);
    }

    typedef SizeClassMap SizeClassMapT;
    static const uptr kNumClasses = SizeClassMap::kNumClasses;
    static const uptr kNumClassesRounded = SizeClassMap::kNumClassesRounded;

private:
    static const uptr kRegionSize = kSpaceSize / kNumClassesRounded;
    // FreeArray is the array of free-d chunks (stored as 4-byte offsets).
    // In the worst case it may reguire kRegionSize/SizeClassMap::kMinSize
    // elements, but in reality this will not happen. For simplicity we
    // dedicate 1/8 of the region's virtual space to FreeArray.
    static const uptr kFreeArraySize = kRegionSize / 8;

    static const bool kUsingConstantSpaceBeg = kSpaceBeg != ~(uptr)0;
    uptr NonConstSpaceBeg;
    uptr SpaceBeg() const
    {
        return kUsingConstantSpaceBeg ? kSpaceBeg : NonConstSpaceBeg;
    }
    uptr SpaceEnd() const
    {
        return  SpaceBeg() + kSpaceSize;
    }
    // kRegionSize must be >= 2^32.
    COMPILER_CHECK((kRegionSize) >= (1ULL << (SANITIZER_WORDSIZE / 2)));
    // kRegionSize must be <= 2^36, see CompactPtrT.
    COMPILER_CHECK((kRegionSize) <= (1ULL << (SANITIZER_WORDSIZE / 2 + 4)));
    // Call mmap for user memory with at least this size.
    static const uptr kUserMapSize = 1 << 16;
    // Call mmap for metadata memory with at least this size.
    static const uptr kMetaMapSize = 1 << 16;
    // Call mmap for free array memory with at least this size.
    static const uptr kFreeArrayMapSize = 1 << 16;
    // Granularity of ReleaseToOs (aka madvise).
    static const uptr kReleaseToOsGranularity = 1 << 12;

    struct ReleaseToOsInfo
    {
        uptr n_freed_at_last_release; // 上一次一共返还的内存的数目
        uptr num_releases; // 尝试向操作系统返还内存的次数
    };

    struct RegionInfo
    {
        BlockingMutex mutex;
        uptr num_freed_chunks;  // Number of elements in the freearray. freearray数组中元素的个数
        uptr mapped_free_array;  // Bytes mapped for freearray. freearray数组的大小
        uptr allocated_user;  // Bytes allocated for user memory.
        uptr allocated_meta;  // Bytes allocated for metadata.
        uptr mapped_user;  // Bytes mapped for user memory.
        uptr mapped_meta;  // Bytes mapped for metadata.
        u32 rand_state; // Seed for random shuffle, used if kRandomShuffleChunks.
        uptr n_allocated, n_freed;  // Just stats.
        ReleaseToOsInfo rtoi; // 向操作系统返还内存的统计信息
    };
    COMPILER_CHECK(sizeof(RegionInfo) >= kCacheLineSize);

    u32 Rand(u32 *state)    // ANSI C linear congruential PRNG.
    {
        return (*state = *state * 1103515245 + 12345) >> 16;
    }

    u32 RandN(u32 *state, u32 n)
    {
        return Rand(state) % n;    // [0, n)
    }

    void RandomShuffle(u32 *a, u32 n, u32 *rand_state)
    {
        if (n <= 1) return;
        for (u32 i = n - 1; i > 0; i--)
            Swap(a[i], a[RandN(rand_state, i + 1)]);
    }

    RegionInfo *GetRegionInfo(uptr class_id) // 每一个sizeclass都对应一个RegionInfo
    {
        CHECK_LT(class_id, kNumClasses);
        RegionInfo *regions = reinterpret_cast<RegionInfo *>(SpaceBeg() + kSpaceSize); // regionInfo数组首地址
        return &regions[class_id];
    }

    uptr GetMetadataEnd(uptr region_beg)
    {
        return region_beg + kRegionSize - kFreeArraySize;
    }

    uptr GetChunkIdx(uptr chunk, uptr size)
    {
        if (!kUsingConstantSpaceBeg)
            chunk -= SpaceBeg();

        uptr offset = chunk % kRegionSize;
        // Here we divide by a non-constant. This is costly.
        // size always fits into 32-bits. If the offset fits too, use 32-bit div.
        if (offset >> (SANITIZER_WORDSIZE / 2))
            return offset / size;
        return (u32)offset / (u32)size;
    }

    CompactPtrT *GetFreeArray(uptr region_beg)
    {
        return reinterpret_cast<CompactPtrT *>(region_beg + kRegionSize -
                                               kFreeArraySize);
    }
	// 保证region的free_array数组足够大
    void EnsureFreeArraySpace(RegionInfo *region, uptr region_beg, uptr num_freed_chunks)
    {
        uptr needed_space = num_freed_chunks * sizeof(CompactPtrT); // 需要的空间
        if (region->mapped_free_array < needed_space)
        {
            CHECK_LE(needed_space, kFreeArraySize);
            uptr new_mapped_free_array = RoundUpTo(needed_space, kFreeArrayMapSize);
            uptr current_map_end = reinterpret_cast<uptr>(GetFreeArray(region_beg)) +
                                   region->mapped_free_array;
            uptr new_map_size = new_mapped_free_array - region->mapped_free_array;
            MapWithCallback(current_map_end, new_map_size); // 重新进行内存映射
            region->mapped_free_array = new_mapped_free_array;
        }
    }

    void PopulateFreeArray(AllocatorStats *stat, uptr class_id,
                                    RegionInfo *region, uptr requested_count);

    bool MaybeReleaseChunkRange(uptr region_beg, uptr chunk_size,
                                CompactPtrT first, CompactPtrT last)
    {
        uptr beg_ptr = CompactPtrToPointer(region_beg, first);
        uptr end_ptr = CompactPtrToPointer(region_beg, last) + chunk_size;
        CHECK_GE(end_ptr - beg_ptr, kReleaseToOsGranularity);
        beg_ptr = RoundUpTo(beg_ptr, kReleaseToOsGranularity);
        end_ptr = RoundDownTo(end_ptr, kReleaseToOsGranularity);
        if (end_ptr == beg_ptr) return false;
        ReleaseMemoryToOS(beg_ptr, end_ptr - beg_ptr);
        return true;
    }

    // Releases some RAM back to OS.
    // Algorithm:
    // * Lock the region.
    // * Sort the chunks.
    // * Find ranges fully covered by free-d chunks
    // * Release them to OS with madvise.
    //
    // TODO(kcc): make sure we don't do it too frequently.
    void ReleaseToOS(uptr class_id); // 将内存返还给操作系统
};
```

#### 2. 第二内存分配器

我们来简单看一下 `LargeMmapAllocator` , 这个内存分配器主要用于分配大块内存,它实现非常简单.下面摘取了它的实现, 删掉了一些不相关的代码.

```c
// sanitizer_allocator.h
// Allocators call these callbacks on mmap/munmap.
struct NoOpMapUnmapCallback
{
  void OnMap(uptr p, uptr size) const { }
  void OnUnmap(uptr p, uptr size) const { }
};

// This class can (de)allocate only large chunks of memory using mmap/unmap.
// The main purpose of this allocator is to cover large and rare allocation
// sizes not covered by more efficient allocators (e.g. SizeClassAllocator64).
template <class MapUnmapCallback = NoOpMapUnmapCallback>
class LargeMmapAllocator 
{
 public:
  void InitLinkerInitialized(bool may_return_null) 
  {
    page_size_ = GetPageSizeCached();
    atomic_store(&may_return_null_, may_return_null, memory_order_relaxed);
  }

  void Init(bool may_return_null) 
  {
    internal_memset(this, 0, sizeof(*this));
    InitLinkerInitialized(may_return_null);
  }
  // 进行大内存的分配
  void *Allocate(AllocatorStats *stat, uptr size, uptr alignment) 
  {
    CHECK(IsPowerOfTwo(alignment));
    uptr map_size = RoundUpMapSize(size);
    if (alignment > page_size_)
      map_size += alignment;
    // Overflow.
    if (map_size < size) return ReturnNullOrDieOnBadRequest();
    uptr map_beg = reinterpret_cast<uptr>(
        MmapOrDie(map_size, "LargeMmapAllocator"));
    CHECK(IsAligned(map_beg, page_size_)); // 这里实际直接调用mmap函数进行内存的分配
    MapUnmapCallback().OnMap(map_beg, map_size); // 这里实际不会干任何事情
    uptr map_end = map_beg + map_size;
    uptr res = map_beg + page_size_;
    if (res & (alignment - 1))  // Align.
      res += alignment - (res & (alignment - 1));
    CHECK(IsAligned(res, alignment));
    CHECK(IsAligned(res, page_size_));
    CHECK_GE(res + size, map_beg);
    CHECK_LE(res + size, map_end);
    Header *h = GetHeader(res);
    h->size = size;
    h->map_beg = map_beg;
    h->map_size = map_size;
    uptr size_log = MostSignificantSetBitIndex(map_size);
    CHECK_LT(size_log, ARRAY_SIZE(stats.by_size_log));
    {
      SpinMutexLock l(&mutex_);
      uptr idx = n_chunks_++;
      chunks_sorted_ = false;
      CHECK_LT(idx, kMaxNumChunks);
      h->chunk_idx = idx;
      chunks_[idx] = h;
      stats.n_allocs++; // 记录下大内存分配的次数
      stats.currently_allocated += map_size; // 累加内存分配的大小
      stats.max_allocated = Max(stats.max_allocated, stats.currently_allocated);
      stats.by_size_log[size_log]++;
      stat->Add(AllocatorStatAllocated, map_size); // 累加到总的内存分配大小中去
      stat->Add(AllocatorStatMapped, map_size);
    }
    return reinterpret_cast<void*>(res);
  }
  // ...
  // 内存释放 
  void Deallocate(AllocatorStats *stat, void *p) 
  {
    Header *h = GetHeader(p);
    {
      SpinMutexLock l(&mutex_);
      uptr idx = h->chunk_idx;
      CHECK_EQ(chunks_[idx], h);
      CHECK_LT(idx, n_chunks_);
      chunks_[idx] = chunks_[n_chunks_ - 1];
      chunks_[idx]->chunk_idx = idx;
      n_chunks_--;
      chunks_sorted_ = false;
      stats.n_frees++;
      stats.currently_allocated -= h->map_size;
      stat->Sub(AllocatorStatAllocated, h->map_size);
      stat->Sub(AllocatorStatMapped, h->map_size);
    }
    MapUnmapCallback().OnUnmap(h->map_beg, h->map_size); // 这里什么也不干
    UnmapOrDie(reinterpret_cast<void*>(h->map_beg), h->map_size); // 这里实际调用unmap回收内存
  }
  // 计算总共使用的内存的数目
  uptr TotalMemoryUsed() 
  {
    SpinMutexLock l(&mutex_);
    uptr res = 0;
    for (uptr i = 0; i < n_chunks_; i++) {
      Header *h = chunks_[i];
      CHECK_EQ(h->chunk_idx, i);
      res += RoundUpMapSize(h->size);
    }
    return res;
  }

  // ....
  // 打印统计信息
  void PrintStats() 
  {
    // 这里打印通过LargeMmap内存分配器分配的内存
    Printf("Stats: LargeMmapAllocator: allocated %zd times, "
           "remains %zd (%zd K) max %zd M; by size logs: ",
           stats.n_allocs, stats.n_allocs - stats.n_frees,
           stats.currently_allocated >> 10, stats.max_allocated >> 20);
    for (uptr i = 0; i < ARRAY_SIZE(stats.by_size_log); i++)
    {
      uptr c = stats.by_size_log[i];
      if (!c) continue;
      Printf("%zd:%zd; ", i, c);
    }
    Printf("\n");
  }
  // ...

 private:
  static const int kMaxNumChunks = 1 << FIRST_32_SECOND_64(15, 18);
  struct Header {
    uptr map_beg;
    uptr map_size;
    uptr size;
    uptr chunk_idx;
  };
  // ...
  uptr RoundUpMapSize(uptr size) 
  {
    return RoundUpTo(size, page_size_) + page_size_;
  }

  uptr page_size_;
  Header *chunks_[kMaxNumChunks];
  uptr n_chunks_;
  uptr min_mmap_, max_mmap_;
  bool chunks_sorted_;
  struct Stats {
    uptr n_allocs, n_frees, currently_allocated, max_allocated, by_size_log[64];
  } stats;
  atomic_uint8_t may_return_null_;
  SpinMutex mutex_;
};
```

下面摘录一下 `MmapOrDie` 以及 `UnmapOrDie` 函数的实现( `sanitizer_posix.cc` ):

```c
    /* 执行mmap操作
     * @param size 需要分配的内存的大小
     */
    void *MmapOrDie(uptr size, const char *mem_type, bool raw_report)
    {
        size = RoundUpTo(size, GetPageSizeCached()); /* 对于4k的页来说,这里要求size至少是4k */
        uptr res = internal_mmap(nullptr, size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANON, -1, 0);
        int reserrno;
        if (internal_iserror(res, &reserrno))
            ReportMmapFailureAndDie(size, mem_type, "allocate", reserrno, raw_report);
        IncreaseTotalMmap(size);
        return (void *)res;
    }
    /* 执行unmap操作
     * @param addr 待回收的首地址
     * @param size 内存块大小
     */
    void UnmapOrDie(void *addr, uptr size)
    {
        if (!addr || !size) return;
        uptr res = internal_munmap(addr, size);
        if (internal_iserror(res))
        {
            Report("ERROR: %s failed to deallocate 0x%zx (%zd) bytes at address %p\n",
                   SanitizerToolName, size, size, addr);
            CHECK("unable to unmap" && 0);
        }
        DecreaseTotalMmap(size);
    }
```

### 1.4 隔离区

为了检测内存访问是否正常,上层应用释放内存之后,asan并不会立即将其归还给操作系统,而是会暂时缓存起来,放在隔离区内.

只有当隔离区缓存的内存达到上限,才会触发内存回收操作.

```c
// sanitizer_quarantine.h
template<typename Node> class QuarantineCache;

struct QuarantineBatch
{
    static const uptr kSize = 1021;
    QuarantineBatch *next;
    uptr size;
    uptr count;
    void *batch[kSize];
};

COMPILER_CHECK(sizeof(QuarantineBatch) <= (1 << 13));  // 8Kb.

// The callback interface is:
// void Callback::Recycle(Node *ptr);
// void *cb.Allocate(uptr size);
// void cb.Deallocate(void *ptr);
template<typename Callback, typename Node>
    class Quarantine   // 隔离区的模板类
{
public:
    typedef QuarantineCache<Callback> Cache;

    explicit Quarantine(LinkerInitialized)
        : cache_(LINKER_INITIALIZED)
        {
        }

    void Init(uptr size, uptr cache_size)
    {
        atomic_store(&max_size_, size, memory_order_release);
        atomic_store(&min_size_, size / 10 * 9, memory_order_release); // 90% of max size.
        max_cache_size_ = cache_size; // 隔离区的最大数目
    }

    uptr GetSize() const
    {
        return atomic_load(&max_size_, memory_order_acquire);
    }

    void Put(Cache *c, Callback cb, Node *ptr, uptr size) // 将内存放入隔离区
    {
        c->Enqueue(cb, ptr, size);
        if (c->Size() > max_cache_size_) // 如果保存的内存数目超过了最大限制
            Drain(c, cb); // 立马启动回收工作
    }
    // 立即释放
    void Drain(Cache *c, Callback cb)
    {
        {
            SpinMutexLock l(&cache_mutex_);
            cache_.Transfer(c);
        }
        if (cache_.Size() > GetSize() && recycle_mutex_.TryLock())
            Recycle(cb);
    }

private:
    // Read-only data.
    char pad0_[kCacheLineSize];
    atomic_uintptr_t max_size_;
    atomic_uintptr_t min_size_;
    uptr max_cache_size_;
    char pad1_[kCacheLineSize];
    SpinMutex cache_mutex_;
    SpinMutex recycle_mutex_;
    Cache cache_;
    char pad2_[kCacheLineSize];

    void Recycle(Callback cb) // 内存回收
    {
        Cache tmp;
        uptr min_size = atomic_load(&min_size_, memory_order_acquire);
        {
            SpinMutexLock l(&cache_mutex_);
            while (cache_.Size() > min_size)
            {
                QuarantineBatch *b = cache_.DequeueBatch();
                tmp.EnqueueBatch(b);
            }
        }
        recycle_mutex_.Unlock();
        DoRecycle(&tmp, cb); // 执行内存回收工作
    }

    void DoRecycle(Cache *c, Callback cb)
    {
        while (QuarantineBatch *b = c->DequeueBatch())
        {
            const uptr kPrefetch = 16;
            CHECK(kPrefetch <= ARRAY_SIZE(b->batch));
            for (uptr i = 0; i < kPrefetch; i++)
                PREFETCH(b->batch[i]);
            for (uptr i = 0, count = b->count; i < count; i++)
            {
                if (i + kPrefetch < count)
                    PREFETCH(b->batch[i + kPrefetch]);
                cb.Recycle((Node*)b->batch[i]); // 内存回收
            }
            cb.Deallocate(b);
        }
    }
};

// Per-thread cache of memory blocks.
template<typename Callback>
    class QuarantineCache   // 隔离区缓冲
{
public:
    explicit QuarantineCache(LinkerInitialized)
    {
    }

    QuarantineCache()
        : size_()
    {
        list_.clear();
    }

    uptr Size() const // 获取隔离区缓存缓存的内存大小
    {
        return atomic_load(&size_, memory_order_relaxed);
    }
    // 向缓冲区中放入数据
    void Enqueue(Callback cb, void *ptr, uptr size)
    {
        if (list_.empty() || list_.back()->count == QuarantineBatch::kSize)
        {
            AllocBatch(cb);
            size += sizeof(QuarantineBatch);  // Count the batch in Quarantine size.
        }
        QuarantineBatch *b = list_.back();
        CHECK(b);
        b->batch[b->count++] = ptr; // 记录下回收的内存
        b->size += size;
        SizeAdd(size);
    }

    void Transfer(QuarantineCache *c)
    {
        list_.append_back(&c->list_);
        SizeAdd(c->Size());
        atomic_store(&c->size_, 0, memory_order_relaxed);
    }

    void EnqueueBatch(QuarantineBatch *b) // 想缓冲区缓存中添加一个QuarantineBatch
    {
        list_.push_back(b);
        SizeAdd(b->size);
    }

    QuarantineBatch *DequeueBatch() // 从缓冲区缓存中取出一个QuarantineBatch
    {
        if (list_.empty())
            return nullptr;
        QuarantineBatch *b = list_.front();
        list_.pop_front();
        SizeSub(b->size);
        return b;
    }

private:
    IntrusiveList<QuarantineBatch> list_; // 链表,用于缓冲数据
    atomic_uintptr_t size_; // 缓冲区大小

    void SizeAdd(uptr add) // 增加缓冲区大小
    {
        atomic_store(&size_, Size() + add, memory_order_relaxed);
    }
    void SizeSub(uptr sub) // 减小缓冲区大小
    {
        atomic_store(&size_, Size() - sub, memory_order_relaxed);
    }

    QuarantineBatch* AllocBatch(Callback cb) // 分配一个新的QuarantineBatch
    {
        QuarantineBatch *b = (QuarantineBatch *)cb.Allocate(sizeof(*b));
        CHECK(b);
        b->count = 0;
        b->size = 0;
        list_.push_back(b);
        return b;
    }
};
```

以上隔离区中涉及的 `Callback` 实际是下面的 `QuarantineCallback` .

```c
struct QuarantineCallback
{
    explicit QuarantineCallback(AllocatorCache *cache)
        : cache_(cache)
    {
    }

    void Recycle(AsanChunk *m); // 内存回收
    {
        CHECK_EQ(m->chunk_state, CHUNK_QUARANTINE);
        atomic_store((atomic_uint8_t*)m, CHUNK_AVAILABLE, memory_order_relaxed);
        CHECK_NE(m->alloc_tid, kInvalidTid);
        CHECK_NE(m->free_tid, kInvalidTid);
        PoisonShadow(m->Beg(),
                     RoundUpTo(m->UsedSize(), SHADOW_GRANULARITY),
                     kAsanHeapLeftRedzoneMagic);
        void *p = reinterpret_cast<void *>(m->AllocBeg());
        if (p != m)
        {
            uptr *alloc_magic = reinterpret_cast<uptr *>(p);
            CHECK_EQ(alloc_magic[0], kAllocBegMagic);
            // Clear the magic value, as allocator internals may overwrite the
            // contents of deallocated chunk, confusing GetAsanChunk lookup.
            alloc_magic[0] = 0;
            CHECK_EQ(alloc_magic[1], reinterpret_cast<uptr>(m));
        }

        // Statistics.
        AsanStats &thread_stats = GetCurrentThreadStats();
        thread_stats.real_frees++;
        thread_stats.really_freed += m->UsedSize();

        get_allocator().Deallocate(cache_, p);
    }

    void *Allocate(uptr size)
    {
        return get_allocator().Allocate(cache_, size, 1, false);
    }

    void Deallocate(void *p)
    {
        get_allocator().Deallocate(cache_, p);
    }

    AllocatorCache *cache_; // 分配器缓存
};

typedef Quarantine<QuarantineCallback, AsanChunk> AsanQuarantine;
typedef AsanQuarantine::Cache QuarantineCache;
```

## 2. 内存分配

翻阅asan的相关代码,最烦人的是CPP满屏的跳转.

```c
enum AllocType {
    FROM_MALLOC = 1,  // Memory block came from malloc, calloc, realloc, etc.
    FROM_NEW = 2,     // Memory block came from operator new.
    FROM_NEW_BR = 3   // Memory block came from operator new [ ]
};

/* 通过malloc来分配内存
 * @param size 要分配的内存大小
 * @param stack 堆栈大小
 */
void *asan_malloc(uptr size, BufferedStackTrace *stack)
{
    return instance.Allocate(size, 8, stack, FROM_MALLOC, true);
}
```

这里实际会调用`Allocator::Allocate`函数:

```c
/* 内存分配
 * @param size 要分配的内存的大小
 * @param alignment 对齐参数
 */
void *Allocate(uptr size, uptr alignment, BufferedStackTrace *stack,
               AllocType alloc_type, bool can_fill)
{
    if (UNLIKELY(!asan_inited))
        AsanInitFromRtl();
    Flags &fl = *flags();
    const uptr min_alignment = SHADOW_GRANULARITY;
    if (alignment < min_alignment)
        alignment = min_alignment; // 对齐参数
    if (size == 0)
    {
        // We'd be happy to avoid allocating memory for zero-size requests, but
        // some programs/tests depend on this behavior and assume that malloc
        // would not return NULL even for zero-size allocations. Moreover, it
        // looks like operator new should never return NULL, and results of
        // consecutive "new" calls must be different even if the allocated size
        // is zero.
        size = 1;
    }
    CHECK(IsPowerOfTwo(alignment)); // 保证要2的幂次对齐
    uptr rz_log = ComputeRZLog(size);
    uptr rz_size = RZLog2Size(rz_log);
    uptr rounded_size = RoundUpTo(Max(size, kChunkHeader2Size), alignment);
    uptr needed_size = rounded_size + rz_size;
    if (alignment > min_alignment)
        needed_size += alignment; // 算出实际要分配的内存大小
    bool using_primary_allocator = true;
    // If we are allocating from the secondary allocator, there will be no
    // automatic right redzone, so add the right redzone manually.
    if (!PrimaryAllocator::CanAllocate(needed_size, alignment)) // 判断是否能够通过第一分配器分配内存
    {
        needed_size += rz_size;
        using_primary_allocator = false;
    }
 	// ...

    AsanThread *t = GetCurrentThread();
    void *allocated;
    bool check_rss_limit = true;
    if (t)
    {
        AllocatorCache *cache = GetAllocatorCache(&t->malloc_storage()); // 尝试从缓存中进行分配
        allocated = allocator.Allocate(cache, needed_size, 8, false, check_rss_limit);
    }
    else
    {
        SpinMutexLock l(&fallback_mutex);
        AllocatorCache *cache = &fallback_allocator_cache;
        allocated = allocator.Allocate(cache, needed_size, 8, false, check_rss_limit);
    }

    if (!allocated) return allocator.ReturnNullOrDieOnOOM();

    if (*(u8 *)MEM_TO_SHADOW((uptr)allocated) == 0 && CanPoisonMemory())
    {
        // Heap poisoning is enabled, but the allocator provides an unpoisoned
        // chunk. This is possible if CanPoisonMemory() was false for some
        // time, for example, due to flags()->start_disabled.
        // Anyway, poison the block before using it for anything else.
        uptr allocated_size = allocator.GetActuallyAllocatedSize(allocated);
        // Heap left redzone
        PoisonShadow((uptr)allocated, allocated_size, kAsanHeapLeftRedzoneMagic); // 地址毒化,将对应的影子内存标记为0xf1
    }

    uptr alloc_beg = reinterpret_cast<uptr>(allocated); // 起始位置
    uptr alloc_end = alloc_beg + needed_size; // 结尾位置
    uptr beg_plus_redzone = alloc_beg + rz_size;
    // user_beg记录的是用户内存(user memory)开始的位置
    uptr user_beg = beg_plus_redzone;
    if (!IsAligned(user_beg, alignment))
        user_beg = RoundUpTo(user_beg, alignment); // 考虑对齐
    uptr user_end = user_beg + size;
    CHECK_LE(user_end, alloc_end);
    // chunk_beg记录是ChunkHeader开始的位置
    uptr chunk_beg = user_beg - kChunkHeaderSize;
    AsanChunk *m = reinterpret_cast<AsanChunk *>(chunk_beg);
    m->alloc_type = alloc_type; // 分配类型
    m->rz_log = rz_log;
    u32 alloc_tid = t ? t->tid() : 0;
    m->alloc_tid = alloc_tid;
    CHECK_EQ(alloc_tid, m->alloc_tid);  // Does alloc_tid fit into the bitfield?
    m->free_tid = kInvalidTid;
    m->from_memalign = user_beg != beg_plus_redzone;
    if (alloc_beg != chunk_beg)
    {
        CHECK_LE(alloc_beg+ 2 * sizeof(uptr), chunk_beg);
        reinterpret_cast<uptr *>(alloc_beg)[0] = kAllocBegMagic; // 第一个字节为魔数值
        reinterpret_cast<uptr *>(alloc_beg)[1] = chunk_beg; // 第二个字节指向ChunkHeader
    }
    if (using_primary_allocator)
    {
        m->user_requested_size = size; // 记录下分配的内存大小
        CHECK(allocator.FromPrimary(allocated));
    }
    else
    {
        CHECK(!allocator.FromPrimary(allocated));
        m->user_requested_size = SizeClassMap::kMaxSize;
        uptr *meta = reinterpret_cast<uptr *>(allocator.GetMetaData(allocated));
        meta[0] = size;
        meta[1] = chunk_beg;
    }
    m->alloc_context_id = StackDepotPut(*stack); // 记录下堆栈信息, 将堆栈转换为一个唯一的context_id

    uptr size_rounded_down_to_granularity = RoundDownTo(size, SHADOW_GRANULARITY);
    // Unpoison the bulk of the memory region.
    if (size_rounded_down_to_granularity)
        PoisonShadow(user_beg, size_rounded_down_to_granularity, 0); // 地址毒化,标记为地址可用
    // Deal with the end of the region if size is not aligned to granularity.
    if (size != size_rounded_down_to_granularity && CanPoisonMemory())
    {
        u8 *shadow = (u8 *)MemToShadow(user_beg + size_rounded_down_to_granularity);
        *shadow = fl.poison_partial ? (size & (SHADOW_GRANULARITY - 1)) : 0; // 部分地址标记为可用
    }

    AsanStats &thread_stats = GetCurrentThreadStats();
    thread_stats.mallocs++; // 调用malloc次数+1
    thread_stats.malloced += size; // 统计分配内存数目
    thread_stats.malloced_redzones += needed_size - size;
    if (needed_size > SizeClassMap::kMaxSize)
        thread_stats.malloc_large++; // 大内存分配计数
    else
        thread_stats.malloced_by_size[SizeClassMap::ClassID(needed_size)]++;

    void *res = reinterpret_cast<void *>(user_beg);
    if (can_fill && fl.max_malloc_fill_size)
    {
        uptr fill_size = Min(size, (uptr)fl.max_malloc_fill_size);
        REAL(memset)(res, fl.malloc_fill_byte, fill_size);
    }
#if CAN_SANITIZE_LEAKS
    m->lsan_tag = __lsan::DisabledInThisThread() ? __lsan::kIgnored : __lsan::kDirectlyLeaked;
#endif
    // Must be the last mutation of metadata in this function.
    atomic_store((atomic_uint8_t *)m, CHUNK_ALLOCATED, memory_order_release);
    ASAN_MALLOC_HOOK(res, size);
    return res;
}
```

上面的代码实际会调用`CombinedAllocator::Allocate`来分配内存.

```c
/* 内存分配
 * @param size 要申请的内存的大小
 * @param alignment 对齐参数
 */
void *Allocate(AllocatorCache *cache, uptr size, uptr alignment,
               bool cleared = false, bool check_rss_limit = false)
{
    // Returning 0 on malloc(0) may break a lot of code.
    if (size == 0) size = 1;
    if (size + alignment < size) return ReturnNullOrDieOnBadRequest();
    if (check_rss_limit && RssLimitIsExceeded()) return ReturnNullOrDieOnOOM();
    if (alignment > 8)
        size = RoundUpTo(size, alignment);
    void *res;
    bool from_primary = primary_.CanAllocate(size, alignment); // 判断是否能从第一分配器中分配内存
    if (from_primary)
        res = cache->Allocate(&primary_, primary_.ClassID(size)); // 优先从cache中来分配
    else
        res = secondary_.Allocate(&stats_, size, alignment);
    if (alignment > 8)
        CHECK_EQ(reinterpret_cast<uptr>(res) & (alignment - 1), 0);
    if (cleared && res && from_primary)
        internal_bzero_aligned16(res, RoundUpTo(size, 16));
    return res;
}
```

假定我们从缓存中进行分配,会调用`SizeClassAllocator64LocalCache<SizeClassAllocator64<AP64>>::Allocator`:

```c
 /* 内存分配
  * @param class_id 内存大小级别
  */
void *Allocate(SizeClassAllocator *allocator, uptr class_id)
{
    stats_.Add(AllocatorStatAllocated, Allocator::ClassIdToSize(class_id)); // 更新统计信息
    PerClass *c = &per_class_[class_id];
    if (UNLIKELY(c->count == 0))
        Refill(c, allocator, class_id); // 填充缓存
    CHECK_GT(c->count, 0);
    CompactPtrT chunk = c->chunks[--c->count]; // 取出一个空闲的内存块即可
    void *res = reinterpret_cast<void *>(allocator->CompactPtrToPointer(
        allocator->GetRegionBeginBySizeClass(class_id), chunk));
    return res;
}
```

`SizeClassAllocator64LocalCache<SizeClassAllocator64<AP64>>::Refill`:

```c
/* 重新申请内存 */
void Refill(PerClass *c, SizeClassAllocator *allocator, uptr class_id)
{
    InitCache();
    uptr num_requested_chunks = SizeClassMap::MaxCachedHint(class_id);
    allocator->GetFromAllocator(&stats_, class_id, c->chunks, num_requested_chunks);
    c->count = num_requested_chunks;
}
```

申请内存其实会调用`SizeClassAllocator64::GetFromAllocator`:

```c
void GetFromAllocator(AllocatorStats *stat, uptr class_id, CompactPtrT *chunks, uptr n_chunks)
{
    RegionInfo *region = GetRegionInfo(class_id);
    uptr region_beg = GetRegionBeginBySizeClass(class_id);
    CompactPtrT *free_array = GetFreeArray(region_beg);

    BlockingMutexLock l(&region->mutex);
    if (UNLIKELY(region->num_freed_chunks < n_chunks))
    {
        PopulateFreeArray(stat, class_id, region, n_chunks - region->num_freed_chunks);
        CHECK_GE(region->num_freed_chunks, n_chunks);
    }
    region->num_freed_chunks -= n_chunks;
    uptr base_idx = region->num_freed_chunks;
    for (uptr i = 0; i < n_chunks; i++)
        chunks[i] = free_array[base_idx + i]; // 将内存块放入数组
    region->n_allocated += n_chunks; // 更新统计信息
}
```

`SizeClassAllocator64::PopulateFreeArray`:

```c
void PopulateFreeArray(AllocatorStats *stat, uptr class_id,
                                RegionInfo *region, uptr requested_count)
{
    // region->mutex is held.
    uptr size = ClassIdToSize(class_id); // class_id对应级别的内存大小
    uptr beg_idx = region->allocated_user; // 起始位置
    uptr end_idx = beg_idx + requested_count * size; // 终止位置
    uptr region_beg = GetRegionBeginBySizeClass(class_id);
    if (end_idx > region->mapped_user)
    {
        if (!kUsingConstantSpaceBeg && region->mapped_user == 0)
            region->rand_state = static_cast<u32>(region_beg >> 12);  // From ASLR.
        // Do the mmap for the user memory.
        uptr map_size = kUserMapSize;
        while (end_idx > region->mapped_user + map_size)
            map_size += kUserMapSize;
        CHECK_GE(region->mapped_user + map_size, end_idx);
        MapWithCallback(region_beg + region->mapped_user, map_size); // 向操作系统申请内存
        stat->Add(AllocatorStatMapped, map_size); // 更新统计信息
        region->mapped_user += map_size;
    }
    CompactPtrT *free_array = GetFreeArray(region_beg);
    uptr total_count = (region->mapped_user - beg_idx) / size; // 内存分块
    uptr num_freed_chunks = region->num_freed_chunks;
    EnsureFreeArraySpace(region, region_beg, num_freed_chunks + total_count);
    for (uptr i = 0; i < total_count; i++)
    {
        uptr chunk = beg_idx + i * size;
        free_array[num_freed_chunks + total_count - 1 - i] = PointerToCompactPtr(0, chunk);
    }
    if (kRandomShuffleChunks)
        RandomShuffle(&free_array[num_freed_chunks], total_count, &region->rand_state);
    region->num_freed_chunks += total_count;
    region->allocated_user += total_count * size;
    CHECK_LE(region->allocated_user, region->mapped_user);

    region->allocated_meta += total_count * kMetadataSize;
    if (region->allocated_meta > region->mapped_meta)
    {
        uptr map_size = kMetaMapSize;
        while (region->allocated_meta > region->mapped_meta + map_size)
            map_size += kMetaMapSize;
        // Do the mmap for the metadata.
        CHECK_GE(region->mapped_meta + map_size, region->allocated_meta);
        MapWithCallback(GetMetadataEnd(region_beg) - region->mapped_meta - map_size, map_size); // 为元数据申请内存
        region->mapped_meta += map_size;
    }
    CHECK_LE(region->allocated_meta, region->mapped_meta);
    if (region->mapped_user + region->mapped_meta > kRegionSize - kFreeArraySize)
    {
        Printf("%s: Out of memory. Dying. ", SanitizerToolName);
        Printf("The process has exhausted %zuMB for size class %zu.\n",
               kRegionSize / 1024 / 1024, size);
        Die();
    }
}
```

## 3. 地址毒化

### 3.1 shadow address

对于asan分配的每块内存,都有一个对应的影子内存(shadow address)来进行描述.它们之间的大小关系为8:1--也就是说1个字节的影子内存可以用来描述8个字节的实际内存状态.

asan当前使用的状态如下:

```c
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00                   // 影子内存对应的实际内存可以寻址(访问)
  Partially addressable: 01 02 03 04 05 06 07 // 仅有部分内存可以寻址(访问)
  // 01表示,前1个字节可寻址,后7个字节不可寻址
  // 02表示,前2个字节可寻址,后6个字节不可寻址
  // 03表示,前3个字节可寻址,后5个字节不可寻址
  // ...
  Heap left redzone:     fa (实际上Heap right redzone也是fa)
  Freed Heap region:     fd
  Stack left redzone:    f1
  Stack mid redzone:     f2
  Stack right redzone:   f3
  Stack after return:    f5
  Stack use after scope: f8
  Global redzone:        f9
  Global init order:     f6
  Poisoned by user:      f7
  Container overflow:    fc
  Array cookie:          ac
  Intra object redzone:  bb
  ASan internal:         fe
  Left alloca redzone:   ca
  Right alloca redzone:  cb
  Shadow gap:            cc
  
// These magic values are written to shadow for better error reporting.
const int kAsanHeapLeftRedzoneMagic = 0xfa;
const int kAsanHeapFreeMagic = 0xfd;
const int kAsanStackLeftRedzoneMagic = 0xf1;
const int kAsanStackMidRedzoneMagic = 0xf2;
const int kAsanStackRightRedzoneMagic = 0xf3;
const int kAsanStackAfterReturnMagic = 0xf5;
const int kAsanInitializationOrderMagic = 0xf6;
const int kAsanUserPoisonedMemoryMagic = 0xf7;
const int kAsanContiguousContainerOOBMagic = 0xfc;
const int kAsanStackUseAfterScopeMagic = 0xf8;
const int kAsanGlobalRedzoneMagic = 0xf9;
const int kAsanInternalHeapMagic = 0xfe;
const int kAsanArrayCookieMagic = 0xac;
const int kAsanIntraObjectRedzone = 0xbb;
const int kAsanAllocaLeftMagic = 0xca;
const int kAsanAllocaRightMagic = 0xcb;
```

asan一般使用`PoisonShadow`函数来为影子内存打标记:

```c
/* 将地址毒化
 * @param addr 起始地址
 * @param size 长度
 * @param value 将从addr开始的size长度的地址空间都标记为value
 */
void PoisonShadow(uptr addr, uptr size, u8 value)
{
    if (!CanPoisonMemory()) return;
    CHECK(AddrIsAlignedByGranularity(addr));
    CHECK(AddrIsInMem(addr));
    CHECK(AddrIsAlignedByGranularity(addr + size));
    CHECK(AddrIsInMem(addr + size - SHADOW_GRANULARITY));
    CHECK(REAL(memset));
    FastPoisonShadow(addr, size, value);
}
```

最终会调用`FastPoisonShadow`来将地址毒化:

```c
// Fast versions of PoisonShadow and PoisonShadowPartialRightRedzone that
// assume that memory addresses are properly aligned. Use in
// performance-critical code with care.
void FastPoisonShadow(uptr aligned_beg, uptr aligned_size, u8 value)
{
    DCHECK(CanPoisonMemory());
    uptr shadow_beg = MEM_TO_SHADOW(aligned_beg);
    uptr shadow_end = MEM_TO_SHADOW(aligned_beg + aligned_size - SHADOW_GRANULARITY) + 1;
    // FIXME: Page states are different on Windows, so using the same interface
    // for mapping shadow and zeroing out pages doesn't "just work", so we should
    // probably provide higher-level interface for these operations.
    // For now, just memset on Windows.
    if (value ||
        SANITIZER_WINDOWS == 1 ||
        shadow_end - shadow_beg < common_flags()->clear_shadow_mmap_threshold)
    {
        // 将对应地址的值赋值为value即可
        REAL(memset)((void*)shadow_beg, value, shadow_end - shadow_beg);
    }
    else
    {
        uptr page_size = GetPageSizeCached(); // 页大小
        uptr page_beg = RoundUpTo(shadow_beg, page_size);
        uptr page_end = RoundDownTo(shadow_end, page_size);

        if (page_beg >= page_end)
        {
            REAL(memset)((void *)shadow_beg, 0, shadow_end - shadow_beg);
        }
        else
        {
            if (page_beg != shadow_beg)
            {
                REAL(memset)((void *)shadow_beg, 0, page_beg - shadow_beg);
            }
            if (page_end != shadow_end)
            {
                REAL(memset)((void *)page_end, 0, shadow_end - page_end);
            }
            ReserveShadowMemoryRange(page_beg, page_end - 1, nullptr);
        }
    }
}
```

### 3.2 normal address与shadow address相互转换

asan内部可以直接通过`MEM_TO_SHADOW`实现实际访问的地址到对应的影子内存地址的映射.

```c
/* 根据传入的地址,得到其对应的shadow memory的地址
 * 一般的转换公式为 shadow memory address = (normal memory address >> 3) + 0x100000000
 */
#define MEM_TO_SHADOW(mem) (((mem) >> SHADOW_SCALE) + (SHADOW_OFFSET))
#define SHADOW_TO_MEM(shadow) (((shadow) - SHADOW_OFFSET) << SHADOW_SCALE)
```

### 3.3 一些定义

```c
// The full explanation of the memory mapping could be found here:
// https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm
//
// Typical shadow mapping on Linux/x86_64 with SHADOW_OFFSET == 0x00007fff8000:
// || `[0x10007fff8000, 0x7fffffffffff]` || HighMem    ||
// || `[0x02008fff7000, 0x10007fff7fff]` || HighShadow ||
// || `[0x00008fff7000, 0x02008fff6fff]` || ShadowGap  ||
// || `[0x00007fff8000, 0x00008fff6fff]` || LowShadow  ||
// || `[0x000000000000, 0x00007fff7fff]` || LowMem     ||
//
// Default Linux/AArch64 (42-bit VMA) mapping:
// || `[0x10000000000, 0x3ffffffffff]` || highmem    ||
// || `[0x0a000000000, 0x0ffffffffff]` || highshadow ||
// || `[0x09000000000, 0x09fffffffff]` || shadowgap  ||
// || `[0x08000000000, 0x08fffffffff]` || lowshadow  ||
// || `[0x00000000000, 0x07fffffffff]` || lowmem     ||
//
static const u64 kDefaultShadowScale = 3;
#define SHADOW_SCALE kDefaultShadowScale
/* 一般情况下,SHADOW_GRANULARITY为8 */
#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
```

## 4. 内存访问

当进程使用asan相关编译参数来编译的时候,编译器会帮你进行插桩.

举个例子,如果你有一条指令,要读取4字节的数据,编译器会在读取指令之前,插入`__asan_load4_xxx`,来检测读取是否合法.

同理,如果要写入4字节的数据,编译器会在写入指令之前,插入`__asan_store4_xxx`,来检测写入是否合法.

我这里举一个非常简单的例子:

```c
// main.c
#include <stdio.h>
#include <stdlib.h>

int main()
{
        void *ptr = malloc(10);
        int i = *(int *)ptr;
        *((int *)ptr + 1)  = 10;
        return 0;
}
```

对以上的main.c进行编译:

```shell
gcc -g -O0 -fsanitize=address -o dummy main.c
```

编译完成之后,再执行反汇编:

```shell
objdump -dS dummy
```

可以得到main函数的汇编代码:

```assembly
#include <stdio.h>
#include <stdlib.h>

int main()
{
    1175:       55                      push   %rbp
    1176:       48 89 e5                mov    %rsp,%rbp
    1179:       48 83 ec 10             sub    $0x10,%rsp
        void *ptr = malloc(10);
    117d:       bf 0a 00 00 00          mov    $0xa,%edi         ; 参数10放入edi寄存器
    1182:       e8 e9 fe ff ff          callq  1070 <malloc@plt> ; 调用malloc
    1187:       48 89 45 f8             mov    %rax,-0x8(%rbp)   ; 将结果放入ptr之中(-0x8(%rbp))
        int i = *(int *)ptr;
    118b:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    118f:       48 89 c2                mov    %rax,%rdx
    1192:       48 c1 ea 03             shr    $0x3,%rdx
    1196:       48 81 c2 00 80 ff 7f    add    $0x7fff8000,%rdx
    119d:       0f b6 12                movzbl (%rdx),%edx
    11a0:       84 d2                   test   %dl,%dl
    11a2:       40 0f 95 c6             setne  %sil
    11a6:       48 89 c1                mov    %rax,%rcx
    11a9:       83 e1 07                and    $0x7,%ecx
    11ac:       83 c1 03                add    $0x3,%ecx
    11af:       38 d1                   cmp    %dl,%cl
    11b1:       0f 9d c2                setge  %dl
    11b4:       21 f2                   and    %esi,%edx
    11b6:       84 d2                   test   %dl,%dl
    11b8:       74 08                   je     11c2 <main+0x4d>
    11ba:       48 89 c7                mov    %rax,%rdi
    11bd:       e8 6e fe ff ff          callq  1030 <__asan_report_load4@plt> ; 前面全部是检测代码
    11c2:       48 8b 45 f8             mov    -0x8(%rbp),%rax	 ; 将ptr的值取出,放入rax寄存器
    11c6:       8b 00                   mov    (%rax),%eax       ; rax寄存器指向地址的值取出,放入eax寄存器
    11c8:       89 45 f4                mov    %eax,-0xc(%rbp)   ; 将eax寄存器的值放入i(-0xc(%rbp))
        *((int *)ptr + 1)  = 10;
    11cb:       48 8b 45 f8             mov    -0x8(%rbp),%rax   ; 将ptr的值放入rax寄存器
    11cf:       48 8d 48 04             lea    0x4(%rax),%rcx    ; ptr + 4放入rcx寄存器
    11d3:       48 89 c8                mov    %rcx,%rax
    11d6:       48 89 c2                mov    %rax,%rdx
    11d9:       48 c1 ea 03             shr    $0x3,%rdx
    11dd:       48 81 c2 00 80 ff 7f    add    $0x7fff8000,%rdx
    11e4:       0f b6 12                movzbl (%rdx),%edx
    11e7:       84 d2                   test   %dl,%dl
    11e9:       40 0f 95 c7             setne  %dil
    11ed:       48 89 c6                mov    %rax,%rsi
    11f0:       83 e6 07                and    $0x7,%esi
    11f3:       83 c6 03                add    $0x3,%esi
    11f6:       40 38 d6                cmp    %dl,%sil
    11f9:       0f 9d c2                setge  %dl
    11fc:       21 fa                   and    %edi,%edx
    11fe:       84 d2                   test   %dl,%dl
    1200:       74 08                   je     120a <main+0x95>
    1202:       48 89 c7                mov    %rax,%rdi
    1205:       e8 36 fe ff ff          callq  1040 <__asan_report_store4@plt>
    120a:       c7 01 0a 00 00 00       movl   $0xa,(%rcx)      ; 将10放入rcx寄存器所指向的内存
        return 0;
    1210:       b8 00 00 00 00          mov    $0x0,%eax
}
```

如果不带asan参数来编译:

```shell
gcc -g -O0  -o dummy main.c
```

反汇编之后,我们同样可以得到下面的汇编代码:

```assembly
#include <stdio.h>
#include <stdlib.h>

int main()
{
    1135:       55                      push   %rbp
    1136:       48 89 e5                mov    %rsp,%rbp
    1139:       48 83 ec 10             sub    $0x10,%rsp
        void *ptr = malloc(10);
    113d:       bf 0a 00 00 00          mov    $0xa,%edi
    1142:       e8 e9 fe ff ff          callq  1030 <malloc@plt>
    1147:       48 89 45 f8             mov    %rax,-0x8(%rbp)
        int i = *(int *)ptr;
    114b:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    114f:       8b 00                   mov    (%rax),%eax
    1151:       89 45 f4                mov    %eax,-0xc(%rbp)
        *((int *)ptr + 1)  = 10;
    1154:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1158:       48 83 c0 04             add    $0x4,%rax
    115c:       c7 00 0a 00 00 00       movl   $0xa,(%rax)
        return 0;
    1162:       b8 00 00 00 00          mov    $0x0,%eax
}
```

得到的结果和我们所预期的是一致的,gcc确实进行了插桩处理,每一次读/写内存,基本都会执行检测代码,因此asan确实会拖慢运行速度.

gcc怎么来插桩的,我暂时没有太多兴趣,本篇文章不会叙述,感兴趣的同学可以去查找一下相关资料,就使用asan而言,我们只需要知道,它插桩了即可.

### 4.1 检测短内存读取与访问

我们来看一下,`__asan_loadx_xxx`, `__asan_storex_xxx`之类的函数是如何来实现的.

```c
#define ASAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, exp_arg, fatal) \
    uptr sp = MEM_TO_SHADOW(addr);                                             \
    uptr s = size <= SHADOW_GRANULARITY ? *reinterpret_cast<u8 *>(sp)          \
                                        : *reinterpret_cast<u16 *>(sp);        \
    if (UNLIKELY(s)) {                                                         \
      if (UNLIKELY(size >= SHADOW_GRANULARITY ||                               \
                   ((s8)((addr & (SHADOW_GRANULARITY - 1)) + size - 1)) >=     \
                       (s8)s)) {                                               \
        if (__asan_test_only_reported_buggy_pointer) {                         \
          *__asan_test_only_reported_buggy_pointer = addr;                     \
        } else {                                                               \
          GET_CALLER_PC_BP_SP;                                                 \
          ReportGenericError(pc, bp, sp, addr, is_write, size, exp_arg,        \
                              fatal);                                          \
        }                                                                      \
      }                                                                        \
    }

#define ASAN_MEMORY_ACCESS_CALLBACK(type, is_write, size)                      \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE                                      \
  void __asan_##type##size(uptr addr) {                                        \
    ASAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, 0, true)            \
  }                                                                            \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE                                      \
  void __asan_exp_##type##size(uptr addr, u32 exp) {                           \
    ASAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, exp, true)          \
  }                                                                            \
  extern "C" NOINLINE INTERFACE_ATTRIBUTE                                      \
  void __asan_##type##size ## _noabort(uptr addr) {                            \
    ASAN_MEMORY_ACCESS_CALLBACK_BODY(type, is_write, size, 0, false)           \
  }                                                                            \
// 检测读取长度为N(N=1,2,4,8)字节的数据是否存在问题
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 1)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 2)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 4)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 8)
ASAN_MEMORY_ACCESS_CALLBACK(load, false, 16)
// 检测写入长度为N(N=1,2,4,8)字节的数据是否存在问题
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 1)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 2)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 4)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 8)
ASAN_MEMORY_ACCESS_CALLBACK(store, true, 16)
```

举一个简单的例子,将`ASAN_MEMORY_ACCESS_CALLBACK(load, false, 4)`展开,可以得到下面3个函数,这3个函数实现的功能基本一致.

为了简单起见,下面的函数,我们都去掉`extern "C" NOINLINE INTERFACE_ATTRIBUTE`修饰前缀.

```c
void __asan_load4(uptr addr) // 加载4字节的数据
{
    uptr sp = MEM_TO_SHADOW(addr);
    //uptr s = 4 <= SHADOW_GRANULARITY ? *reinterpret_cast<u8 *>(sp) : *reinterpret_cast<u16 *>(sp);
    uptr s = *reinterpret_cast<u8 *>(sp);
    if (UNLIKELY(s)) // 大多数情况下,加载是不存在问题的,所以unlikely
    {
        // shadow addr的1个字节代表normal addr的8个字节,假定shadow addr s <-> normal addr [b, b+8)
        // 给定addr位于[b, b+8)之内, addr & 7 可以确定addr位于[b, b+8)中的哪一个位置
        // 假定从addr开始的size个字节都可以访问,那么它对应的shadow addr s的值要大于addr & 7 + size - 1 
        // 举个例子:
        // addr为0x0,访问4个字节 -> 4 (至少要保证4个字节可以访问=> [0x0, 0x4))
        // addr为0x1,访问4个字节 -> 5 (至少要保证5个字节可以访问=> [0x0, 0x5))
        // addr为0x2,访问4个字节 -> 6 (至少要保证6个字节可以访问=> [0x0, 0x6))
        // 因此 (addr & 7) + size <= s => (addr & 7) + size - 1 < s
        // (addr & 7) + size - 1 >= s 则说明存在问题,也就是访问了不应当访问的地址
        // * asan分配内存的时候,可以保证所有分配出去的内存块的首地址都是8字节对齐
        if (UNLIKELY(1 >= SHADOW_GRANULARITY ||
                     ((s8)((addr & (SHADOW_GRANULARITY - 1)) + 4 - 1)) >= (s8)s)) 
        {
            if (__asan_test_only_reported_buggy_pointer) 
            {
                *__asan_test_only_reported_buggy_pointer = addr;
            }
            else
            {
                GET_CALLER_PC_BP_SP;
                ReportGenericError(pc, bp, sp, addr, false, 4, 0, true);
            }
        }
    }
}

void __asan_exp_load4(uptr addr, u32 exp)
{
    uptr sp = MEM_TO_SHADOW(addr);
    uptr s = 4 <=HADOW_GRANULARITY ? *reinterpret_cast<u8 *>(sp) : *reinterpret_cast<u16 *>(sp);
    if (UNLIKELY(s))
    {
        if (UNLIKELY(4>= SHADOW_GRANULARITY || 
                     ((s8)((addr & (SHADOW_GRANULARITY - 1)) + 4 - 1)) >= (s8)s))
        {
            if (__asan_test_only_reported_buggy_pointer)
            {
                *__asan_test_only_reported_buggy_pointer = addr;
            }
            else
            {
                GET_CALLER_PC_BP_SP;
                ReportGenericError(pc, bp, sp, addr, false, 4, exp, true);
            }
        }
    }
}

void __asan_load4_noabort(uptr addr)
{
    uptr sp = MEM_TO_SHADOW(addr);
    uptr s = 4 <= SHADOW_GRANULARITY ? *reinterpret_cast<u8 *>(sp) : *reinterpret_cast<u16 *>(sp);
    if (UNLIKELY(s)) 
    {
        if (UNLIKELY(4 >= SHADOW_GRANULARITY || 
                     ((s8)((addr & (SHADOW_GRANULARITY - 1)) + 4 - 1)) >= (s8)s)) 
        {
            if (__asan_test_only_reported_buggy_pointer)
            {
                *__asan_test_only_reported_buggy_pointer = addr;
            } 
            else
            {
                GET_CALLER_PC_BP_SP;
                ReportGenericError(pc, bp, sp, addr, false, 4, 0, false);
            }
        }
    }
}
```

将`ASAN_MEMORY_ACCESS_CALLBACK(store, true, 4)`展开,可以得到下面3个函数,这3个函数实现的功能基本一致.

```c
void __asan_store4(uptr addr)
{
    uptr sp = MEM_TO_SHADOW(addr);
    uptr s = 4 <= SHADOW_GRANULARITY ? *reinterpret_cast<u8 *>(sp) : *reinterpret_cast<u16 *>(sp);
    if (UNLIKELY(s)) 
    {
        if (UNLIKELY(4 >= SHADOW_GRANULARITY || 
                     ((s8)((addr & (SHADOW_GRANULARITY - 1)) + 4 - 1)) >= (s8)s)) 
        {
            if (__asan_test_only_reported_buggy_pointer) 
            {
                *__asan_test_only_reported_buggy_pointer = addr;
            }
            else 
            {
                GET_CALLER_PC_BP_SP;
                ReportGenericError(pc, bp, sp, addr, true, 4, 0, true);
            }
        }
    }
}

void __asan_exp_store4(uptr addr, u32 exp)
{
    uptr sp = MEM_TO_SHADOW(addr);
    uptr s = 4 <= SHADOW_GRANULARITY ? *reinterpret_cast<u8 *>(sp) : *reinterpret_cast<u16 *>(sp);
    if (UNLIKELY(s)) 
    {
        if (UNLIKELY(4 >= SHADOW_GRANULARITY || 
                     ((s8)((addr & (SHADOW_GRANULARITY - 1)) + 4 - 1)) >= (s8)s)) 
        {
            if (__asan_test_only_reported_buggy_pointer) 
            {
                *__asan_test_only_reported_buggy_pointer = addr;
            }
            else 
            {
                GET_CALLER_PC_BP_SP;
                ReportGenericError(pc, bp, sp, addr, true, 4, exp, true);
            }
        }
    }
}

void __asan_store4_noabort(uptr addr)
{
    uptr sp = MEM_TO_SHADOW(addr);
    uptr s = 4 <= SHADOW_GRANULARITY ? *reinterpret_cast<u8 *>(sp) : *reinterpret_cast<u16 *>(sp);
    if (UNLIKELY(s))
    {
        if (UNLIKELY(4 >= SHADOW_GRANULARITY || 
                     ((s8)((addr & (SHADOW_GRANULARITY - 1)) + 4 - 1)) >= (s8)s)) 
        {
            if (__asan_test_only_reported_buggy_pointer) 
            {
                *__asan_test_only_reported_buggy_pointer = addr;
            }
            else 
            {
                GET_CALLER_PC_BP_SP;
                ReportGenericError(pc, bp, sp, addr, true, 4, 0, false);
            }
        }
    }
}
```

### 4.2 检测长内存的读取与访问

这里省略了`__asan_loadN_noabort`, `__asan_storeN_noabort`等近似函数.

```c
void __asan_loadN(uptr addr, uptr size)
{
    if (__asan_region_is_poisoned(addr, size))
    {
        GET_CALLER_PC_BP_SP; // 获取调用堆栈等信息
        ReportGenericError(pc, bp, sp, addr, false, size, 0, true);
    }
}

void __asan_storeN(uptr addr, uptr size)
{
    if (__asan_region_is_poisoned(addr, size))
    {
        GET_CALLER_PC_BP_SP;
        ReportGenericError(pc, bp, sp, addr, true, size, 0, true);
    }
}
```

这里面有一个重量级的函数`__asan_region_is_poisoned`用于判断地址是否毒化:

```c
/* 判断地址是否被毒化(不可访问)
 */
uptr __asan_region_is_poisoned(uptr beg, uptr size)
{
    if (!size) return 0;
    uptr end = beg + size;
    if (!AddrIsInMem(beg)) return beg;
    if (!AddrIsInMem(end)) return end;
    CHECK_LT(beg, end);
    uptr aligned_b = RoundUpTo(beg, SHADOW_GRANULARITY);
    uptr aligned_e = RoundDownTo(end, SHADOW_GRANULARITY);
    uptr shadow_beg = MemToShadow(aligned_b); // shadow_addr起始地址
    uptr shadow_end = MemToShadow(aligned_e); // shadow_addr结束地址
    // First check the first and the last application bytes,
    // then check the SHADOW_GRANULARITY-aligned region by calling
    // mem_is_zero on the corresponding shadow.
    if (!__asan::AddressIsPoisoned(beg) &&
        !__asan::AddressIsPoisoned(end - 1) &&
        (shadow_end <= shadow_beg ||
         __sanitizer::mem_is_zero((const char *)shadow_beg, shadow_end - shadow_beg)))
        return 0; // 表示没有被毒化
    // The fast check failed, so we have a poisoned byte somewhere.
    // Find it slowly.
    for (; beg < end; beg++)
        if (__asan::AddressIsPoisoned(beg))
            return beg;
    UNREACHABLE("mem_is_zero returned false, but poisoned byte was not found");
    return 0;
}
```

## 5. 内存回收

上层应用所使用的`free`,`delete`等函数,最终都会调用到`asan_free`来回收内存:

```c
void asan_free(void *ptr, BufferedStackTrace *stack, AllocType alloc_type)
{
    instance.Deallocate(ptr, 0, stack, alloc_type);
}
```

实际上会调用`Allocator::Deallocate`函数:

```c
// Set quarantine flag if chunk is allocated, issue ASan error report on
// available and quarantined chunks. Return true on success, false otherwise.
bool AtomicallySetQuarantineFlagIfAllocated(AsanChunk *m, void *ptr, BufferedStackTrace *stack)
{
    u8 old_chunk_state = CHUNK_ALLOCATED;
    // Flip the chunk_state atomically to avoid race on double-free.
    if (!atomic_compare_exchange_strong((atomic_uint8_t *)m, &old_chunk_state,
                                        CHUNK_QUARANTINE,
                                        memory_order_acquire)) // 切换chunk的状态,由CHUNK_ALLOCATED -> CHUNK_QUARANTINE
    {
        ReportInvalidFree(ptr, old_chunk_state, stack);
        // It's not safe to push a chunk in quarantine on invalid free.
        return false;
    }
    CHECK_EQ(CHUNK_ALLOCATED, old_chunk_state);
    return true;
}

/* 内存回收
 * @param ptr 要回收的内存地址
 * @param stack 调用堆栈
 */
void Deallocate(void *ptr, uptr delete_size, BufferedStackTrace *stack, AllocType alloc_type)
{
    uptr p = reinterpret_cast<uptr>(ptr);
    if (p == 0) return;

    uptr chunk_beg = p - kChunkHeaderSize; // chunk_beg指向chunkheader
    AsanChunk *m = reinterpret_cast<AsanChunk *>(chunk_beg);

    ASAN_FREE_HOOK(ptr);
    // Must mark the chunk as quarantined before any changes to its metadata.
    // Do not quarantine given chunk if we failed to set CHUNK_QUARANTINE flag.
    if (!AtomicallySetQuarantineFlagIfAllocated(m, ptr, stack)) return; // 将内存块状态标记为CHUNK_QUARANTINE

    if (m->alloc_type != alloc_type) // 申请和释放不匹配需要报告
    {
        if (atomic_load(&alloc_dealloc_mismatch, memory_order_acquire))
        {
            ReportAllocTypeMismatch((uptr)ptr, stack, (AllocType)m->alloc_type,
                                    (AllocType)alloc_type);
        }
    }

    if (delete_size && flags()->new_delete_type_mismatch &&
        delete_size != m->UsedSize())
    {
        ReportNewDeleteSizeMismatch(p, delete_size, stack);
    }

    QuarantineChunk(m, ptr, stack, alloc_type); // 将内存放入隔离区
}
```

释放的内存并不会直接回收给操作系统,而是先放入隔离区.

`Allocator::QuarantineChunk`会将要释放的内存信息放入隔离区,这里需要注意一点,在将内存放入隔离区之前,会将内存毒化,表示这块内存已经释放了,也就是将释放的内存标记为 `0xfd` .

```c
// Expects the chunk to already be marked as quarantined by using
// AtomicallySetQuarantineFlagIfAllocated.
void QuarantineChunk(AsanChunk *m, void *ptr, BufferedStackTrace *stack, AllocType alloc_type)
{
    CHECK_EQ(m->chunk_state, CHUNK_QUARANTINE);
    CHECK_GE(m->alloc_tid, 0);
    if (SANITIZER_WORDSIZE == 64)  // On 32-bits this resides in user area.
        CHECK_EQ(m->free_tid, kInvalidTid);
    AsanThread *t = GetCurrentThread();
    m->free_tid = t ? t->tid() : 0;
    m->free_context_id = StackDepotPut(*stack);
    // Poison the region.
    PoisonShadow(m->Beg(),
                 RoundUpTo(m->UsedSize(), SHADOW_GRANULARITY),
                 kAsanHeapFreeMagic); // 标记内存,将用户分配的内存标记为0xfd,表示已经从heap中释放
	// ...

    // Push into quarantine.
    if (t)
    {
        AsanThreadLocalMallocStorage *ms = &t->malloc_storage();
        AllocatorCache *ac = GetAllocatorCache(ms);
        quarantine.Put(GetQuarantineCache(ms), QuarantineCallback(ac), m, m->UsedSize());
    }
    else
    {
        SpinMutexLock l(&fallback_mutex);
        AllocatorCache *ac = &fallback_allocator_cache;
        quarantine.Put(&fallback_quarantine_cache, QuarantineCallback(ac), m, m->UsedSize());
    }
}
```

如果释放的内存数目达到了隔离区的上限,会触发真正的回收工作,会调用`AsanAllocator::Deallocate`,也就是`CombinedAllocator<PrimaryAllocator, AllocatorCache, SecondaryAllocator>::Deallocate`:

```c
/* 内存释放 */
void Deallocate(AllocatorCache *cache, void *p)
{
    if (!p) return;
    if (primary_.PointerIsMine(p))
        cache->Deallocate(&primary_, primary_.GetSizeClass(p), p); // 优先使用第一分配器来回收小内存
    else
        secondary_.Deallocate(&stats_, p); // 第二分配器来回收大内存
}
```

我们仅仅关注小内存的回收,它实际会调用`SizeClassAllocator64LocalCache<SizeClassAllocator64<AP64>>::Deallocate`:

```c
/* 内存释放
 * @param class_id 内存级别
 * @param p 内存首地址
 */
void Deallocate(SizeClassAllocator *allocator, uptr class_id, void *p)
{
    CHECK_NE(class_id, 0UL);
    CHECK_LT(class_id, kNumClasses);
    // If the first allocator call on a new thread is a deallocation, then
    // max_count will be zero, leading to check failure.
    InitCache();
    stats_.Sub(AllocatorStatAllocated, Allocator::ClassIdToSize(class_id));
    PerClass *c = &per_class_[class_id];
    CHECK_NE(c->max_count, 0UL);
    if (UNLIKELY(c->count == c->max_count)) // 如果内存释放太多,就要进行回收操作
        Drain(c, allocator, class_id, c->max_count / 2);
    CompactPtrT chunk = allocator->PointerToCompactPtr(
        allocator->GetRegionBeginBySizeClass(class_id),
        reinterpret_cast<uptr>(p));
    c->chunks[c->count++] = chunk; // 先放入chunks数组
}
```

`SizeClassAllocator64LocalCache<SizeClassAllocator64<AP64>>::Drain`执行真正的内存回收动作:

```c
void Drain(PerClass *c, SizeClassAllocator *allocator, uptr class_id,
           uptr count)
{
    InitCache();
    CHECK_GE(c->count, count);
    uptr first_idx_to_drain = c->count - count;
    c->count -= count;
    allocator->ReturnToAllocator(&stats_, class_id, &c->chunks[first_idx_to_drain], count);
}
```

`SizeClassAllocator64::ReturnToAllocator`:

```c
// 重新向操作系统申请内存
void MapWithCallback(uptr beg, uptr size)
{
    CHECK_EQ(beg, reinterpret_cast<uptr>(MmapFixedOrDie(beg, size)));
    MapUnmapCallback().OnMap(beg, size);
}

// 保证数组足够大
void EnsureFreeArraySpace(RegionInfo *region, uptr region_beg, uptr num_freed_chunks)
{
    uptr needed_space = num_freed_chunks * sizeof(CompactPtrT);
    if (region->mapped_free_array < needed_space) // 为region重新分配内存
    {
        CHECK_LE(needed_space, kFreeArraySize);
        uptr new_mapped_free_array = RoundUpTo(needed_space, kFreeArrayMapSize);
        uptr current_map_end = reinterpret_cast<uptr>(GetFreeArray(region_beg)) +
            region->mapped_free_array;
        uptr new_map_size = new_mapped_free_array - region->mapped_free_array;
        MapWithCallback(current_map_end, new_map_size);
        region->mapped_free_array = new_mapped_free_array;
    }
}

// 将内存回收至分配器
void ReturnToAllocator(AllocatorStats *stat, uptr class_id, const CompactPtrT *chunks, uptr n_chunks)
{
    RegionInfo *region = GetRegionInfo(class_id); // 获得对应的RegionInfo
    uptr region_beg = GetRegionBeginBySizeClass(class_id);
    CompactPtrT *free_array = GetFreeArray(region_beg);

    BlockingMutexLock l(&region->mutex);
    uptr old_num_chunks = region->num_freed_chunks;
    uptr new_num_freed_chunks = old_num_chunks + n_chunks;
    EnsureFreeArraySpace(region, region_beg, new_num_freed_chunks);
    for (uptr i = 0; i < n_chunks; i++)
        free_array[old_num_chunks + i] = chunks[i]; // 将回收的内存块暂时缓存起来,放入chunks数组
    region->num_freed_chunks = new_num_freed_chunks;
    region->n_freed += n_chunks;
}
```

前面的函数我们其实也看得到,实际并没有将内存还给操作系统,只是缓存了起来,方便后续的分配.

那么什么时候会将内存返还给操作系统呢?

这个需要设置 `asan` 的相关参数, 在本人看的代码之中,需要将 `allocator_release_to_os` 这个参数设置为 `1`, `asan` 启动的时候, 会拉起一个线程,专门跑 `BackgroundThread` 函数,需要注意的是, **如果不设置这个参数, `asan` 不会返还内存给操作系统.**

到了这里,我顺带说一句,低版本的 `asan` 其实都不会返还内存给操作系统,所以 `asan` 进程的内存只增加不减少. 当然, `asan` 会复用这些内存.

高版本的 `asan` 默认也不做这种事情,不过还是提供了相关的运行时参数,用户可以选择将内存返还给操作系统.

```c
// sanitizer_common_libcdep.cc
void BackgroundThread(void *arg)
{
  uptr hard_rss_limit_mb = common_flags()->hard_rss_limit_mb;
  uptr soft_rss_limit_mb = common_flags()->soft_rss_limit_mb;
  bool heap_profile = common_flags()->heap_profile;
  bool allocator_release_to_os = common_flags()->allocator_release_to_os;
  uptr prev_reported_rss = 0;
  uptr prev_reported_stack_depot_size = 0;
  bool reached_soft_rss_limit = false;
  uptr rss_during_last_reported_profile = 0;
  while (true) {
    SleepForMillis(100); // 休眠100ms
    uptr current_rss_mb = GetRSS() >> 20;
    if (Verbosity()) { // 如果需要更多信息
      // If RSS has grown 10% since last time, print some information.
      if (prev_reported_rss * 11 / 10 < current_rss_mb) {
        Printf("%s: RSS: %zdMb\n", SanitizerToolName, current_rss_mb);
        prev_reported_rss = current_rss_mb;
      }
      // If stack depot has grown 10% since last time, print it too.
      StackDepotStats *stack_depot_stats = StackDepotGetStats();
      if (prev_reported_stack_depot_size * 11 / 10 <
          stack_depot_stats->allocated) {
        Printf("%s: StackDepot: %zd ids; %zdM allocated\n",
               SanitizerToolName,
               stack_depot_stats->n_uniq_ids,
               stack_depot_stats->allocated >> 20);
        prev_reported_stack_depot_size = stack_depot_stats->allocated;
      }
    }
    // Check RSS against the limit.
    if (hard_rss_limit_mb && hard_rss_limit_mb < current_rss_mb) {
      Report("%s: hard rss limit exhausted (%zdMb vs %zdMb)\n",
             SanitizerToolName, hard_rss_limit_mb, current_rss_mb);
      DumpProcessMap();
      Die(); // rss如果达到限制, 则立即挂掉
    }
    if (soft_rss_limit_mb) {
      if (soft_rss_limit_mb < current_rss_mb && !reached_soft_rss_limit) {
        reached_soft_rss_limit = true;
        Report("%s: soft rss limit exhausted (%zdMb vs %zdMb)\n",
               SanitizerToolName, soft_rss_limit_mb, current_rss_mb);
        if (SoftRssLimitExceededCallback)
          SoftRssLimitExceededCallback(true);
      } else if (soft_rss_limit_mb >= current_rss_mb &&
                 reached_soft_rss_limit) {
        reached_soft_rss_limit = false;
        if (SoftRssLimitExceededCallback)
          SoftRssLimitExceededCallback(false);
      }
    }
    // allocator_release_to_os设置为true, 而且设置了ReleseCallback,则调用此回调 
    if (allocator_release_to_os && ReleseCallback) ReleseCallback();
    // 如果开启课对分析
    if (heap_profile &&
        current_rss_mb > rss_during_last_reported_profile * 1.1) {
      Printf("\n\nHEAP PROFILE at RSS %zdMb\n", current_rss_mb);
      __sanitizer_print_memory_profile(90);
      rss_during_last_reported_profile = current_rss_mb;
    }
  }
}
```

`ReleseCallback` 实际是 `ReleaseToOS` 函数,它的实现如下:

```c
// asan_allocator.cc
void ReleaseToOS()
{
    instance.ReleaseToOS();
}
```

这里会调用`AsanAllocator::ReleaseToOS`:

```c
// asan_allocator.cc
void ReleaseToOS()
{
    allocator.ReleaseToOS();
}
```

`CombinedAllocator::ReleaseToOS`:

```c
// sanitizer_allocator_combined.h
void ReleaseToOS()
{
    primary_.ReleaseToOS();
}
```

`SizeClassAllocator64::ReleaseToOS`:

```c
// sanitizer_allocator_primary64.h
// Releases some RAM back to OS.
// Algorithm:
// * Lock the region.
// * Sort the chunks.
// * Find ranges fully covered by free-d chunks
// * Release them to OS with madvise.
void ReleaseToOS(uptr class_id)
{
    RegionInfo *region = GetRegionInfo(class_id);
    uptr region_beg = GetRegionBeginBySizeClass(class_id);
    CompactPtrT *free_array = GetFreeArray(region_beg);
    uptr chunk_size = ClassIdToSize(class_id);
    uptr scaled_chunk_size = chunk_size >> kCompactPtrScale;
    const uptr kScaledGranularity = kReleaseToOsGranularity >> kCompactPtrScale;
    BlockingMutexLock l(&region->mutex);
    uptr n = region->num_freed_chunks;
    if (n * chunk_size < kReleaseToOsGranularity)
        return;   // No chance to release anything.
    if ((region->rtoi.n_freed_at_last_release - region->n_freed) * chunk_size < kReleaseToOsGranularity)
        return;  // Nothing new to release.
    SortArray(free_array, n);
    uptr beg = free_array[0];
    uptr prev = free_array[0];
    for (uptr i = 1; i < n; i++)
    {
        uptr chunk = free_array[i];
        CHECK_GT(chunk, prev);
        if (chunk - prev != scaled_chunk_size)
        {
            CHECK_GT(chunk - prev, scaled_chunk_size);
            if (prev + scaled_chunk_size - beg >= kScaledGranularity)
            {
                MaybeReleaseChunkRange(region_beg, chunk_size, beg, prev);
                region->rtoi.n_freed_at_last_release = region->n_freed; // 记录下本次返还的内存的数目
                region->rtoi.num_releases++; // 返还次数+1
            }
            beg = chunk;
        }
        prev = chunk;
    }
}

void ReleaseToOS()
{
    for (uptr class_id = 1; class_id < kNumClasses; class_id++) // 对于每一个类别都要回收内存
        ReleaseToOS(class_id);
}
```

`SizeClassAllocator64::MaybeReleaseChunkRange`:

```c
bool MaybeReleaseChunkRange(uptr region_beg, uptr chunk_size,
                            CompactPtrT first, CompactPtrT last)
{
    uptr beg_ptr = CompactPtrToPointer(region_beg, first);
    uptr end_ptr = CompactPtrToPointer(region_beg, last) + chunk_size;
    CHECK_GE(end_ptr - beg_ptr, kReleaseToOsGranularity);
    beg_ptr = RoundUpTo(beg_ptr, kReleaseToOsGranularity);
    end_ptr = RoundDownTo(end_ptr, kReleaseToOsGranularity);
    if (end_ptr == beg_ptr) return false;
    ReleaseMemoryToOS(beg_ptr, end_ptr - beg_ptr); // 将内存还给操作系统
    return true;
}
```

