# Asan相关逻辑

## noraml memory address 到 shadow memory address

主要的转换函数为 `MemToShadow` :

```c
/* 根据传入的地址,得到其对应的shadow memory的地址
 * 一般的转换公式为 shadow memory address = (normal memory address >> 3) + 0x100000000
 */
static inline uptr MemToShadow(uptr p)
{
    PROFILE_ASAN_MAPPING();
    CHECK(AddrIsInMem(p));
    return MEM_TO_SHADOW(p);
}
```

