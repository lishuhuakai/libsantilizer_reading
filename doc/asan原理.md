由于虚拟机的存在，Android应用开发者们通常不用考虑内存访问相关的错误。而一旦我们深入到Native世界中，原本面容和善的内存便开始凶恶起来。这时，由于程序员写法不规范、逻辑疏漏而导致的内存错误会统统跳到我们面前，对我们嘲讽一番。

这些错误既影响了程序的稳定性，也影响了程序的安全性，因为好多恶意代码就通过内存错误来完成入侵。不过麻烦的是，Native世界中的内存错误很难排查，因为很多时候导致问题的地方和发生问题的地方相隔甚远。为了更好地解决这些问题，各路大神纷纷祭出自己手中的神器，相互PK，相互补充。

ASAN(Address Sanitizer)和HWASAN(Hardware-assisted Address Sanitizer)就是这些工具中的佼佼者。

在ASAN出来之前，市面上的内存调试工具要么慢，要么只能检测部分内存错误，要么这两个缺点都有。总之，不够优秀。

HWASAN则是ASAN的升级版，它利用了64位机器上忽略高位地址的特性，将这些被忽略的高位地址重新利用起来，从而大大降低了工具对于CPU和内存带来的额外负载。

## 1. ASAN

ASAN工具包含两大块：

- 插桩模块(Instrumentation module)
- 一个运行时库(Runtime library)

插桩模块主要会做两件事：

1. 对所有的memory access都去检查该内存所对应的shadow memory的状态。这是静态插桩，因此需要重新编译。
2. 为所有栈上对象和全局对象创建前后的保护区(Poisoned redzone)，为检测溢出做准备。

运行时库也同样会做两件事：

1. 替换默认路径的malloc/free等函数。为所有堆对象创建前后的保护区，将free掉的堆区域隔离(quarantine)一段时间，避免它立即被分配给其他人使用。
2. 对错误情况进行输出，包括堆栈信息。

### 1.1 Shadow Memory

如果想要了解ASAN的实现原理，那么shadow memory将是第一个需要了解的概念。

Shadow memory有一些元数据的思维在里面。它虽然也是内存中的一块区域，但是其中的数据仅仅反应其他正常内存的状态信息。所以可以理解为正常内存的元数据，而正常内存中存储的才是程序真正需要的数据。

Malloc函数返回的地址通常是8字节对齐的，因此任意一个由（对齐的）8字节所组成的内存区域必然落在以下9种状态之中：最前面的k（0≤k≤8）字节是可寻址的，而剩下的8-k字节是不可寻址的。这9种状态便可以用shadow memory中的一个字节来进行编码。

实际上，一个byte可以编码的状态总共有256（2^8）种，因此用在这里绰绰有余。



![img](http://www.zyiz.net/upload/202004/01/202004012301234823.png)



Shadow memory和normal memory的映射关系如上图所示。一个byte的shadow memory反映8个byte normal memory的状态。那如何根据normal memory的地址找到它对应的shadow memory呢？

对于64位机器上的Android而言，二者的转换公式如下：

`Shadow memory address = (Normal memory address >> 3) + 0x100000000`

右移三位的目的是为了完成 8➡1的映射，而加一个offset是为了和Normal memory区分开来。最终内存空间种会存在如下的映射关系：



![img](http://www.zyiz.net/upload/202004/01/202004012301235175.png)



Bad代表的是shadow memory的shadow memory，因此其中数据没有意义，该内存区域不可使用。

上文中提到，8字节组成的memory region共有9中状态：

- 1~7个字节可寻址（共七种），shadow memory的值为1~7。
- 8个字节都可寻址，shadow memory的值为0。
- 0个字节可寻址，shadow memory的值为负数。

为什么0个字节可寻址的情况shadow memory不为0，而是负数呢？是因为0个字节可寻址其实可以继续分为多种情况，譬如：

- 这块区域是heap redzones
- 这块区域是stack redzones
- 这块区域是global redzones
- 这块区域是freed memory

对所有0个字节可寻址的normal memory region的访问都是非法的，ASAN将会报错。而根据其shadow memory的值便可以具体判断是哪一种错。

```shell
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
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
```

### 1.2 检测算法

```c
ShadowAddr = (Addr >> 3) + Offset;
k = *ShadowAddr;
if (k != 0 && ((Addr & 7) + AccessSize > k))
    ReportAndCrash(Addr);
```

在每次内存访问时，都会执行如上的伪代码，以判断此次内存访问是否合规。

首先根据normal memory的地址找到对应shadow memory的地址，然后取出其中存取的byte值：k。

- k!=0，说明Normal memory region中的8个字节并不是都可以被寻址的。
- Addr & 7，将得知此次内存访问是从memory region的第几个byte开始的。
- AccessSize是此次内存访问需要访问的字节长度。
- (Addr&7)+AccessSize > k，则说明此次内存访问将会访问到不可寻址的字节。（具体可分为k大于0和小于0两种情况来分析）

当此次内存访问可能会访问到不可寻址的字节时，ASAN会报错并结合shadow memory中具体的值明确错误类型。

### 1.3 典型错误

#### 1.3.1 Use-After-Free

想要检测UseAfterFree的错误，需要有两点保证：

1. 已经free掉的内存区域需要被标记成特殊的状态。在ASAN的实现里，free掉的normal memory对应的shadow memory值为0xfd（猜测有freed的意思）。
2. 已经free掉的内存区域需要放入隔离区一段时间，防止发生错误时该区域已经通过malloc重新分配给其他人使用。一旦分配给其他人使用，则可能漏掉UseAfterFree的错误。

测试代码：

```c
// RUN: clang -O -g -fsanitize=address %t && ./a.out
int main(int argc, char **argv) {
  int *array = new int[100];
  delete [] array;
  return array[argc];  // BOOM
}
```

ASAN输出的错误信息：

```shell
=================================================================
==6254== ERROR: AddressSanitizer: heap-use-after-free on address 0x603e0001fc64 at pc 0x417f6a bp 0x7fff626b3250 sp 0x7fff626b3248
READ of size 4 at 0x603e0001fc64 thread T0
    #0 0x417f69 in main example_UseAfterFree.cc:5
    #1 0x7fae62b5076c (/lib/x86_64-linux-gnu/libc.so.6+0x2176c)
    #2 0x417e54 (a.out+0x417e54)
0x603e0001fc64 is located 4 bytes inside of 400-byte region [0x603e0001fc60,0x603e0001fdf0)
freed by thread T0 here:
    #0 0x40d4d2 in operator delete[](void*) /home/kcc/llvm/projects/compiler-rt/lib/asan/asan_new_delete.cc:61
    #1 0x417f2e in main example_UseAfterFree.cc:4
previously allocated by thread T0 here:
    #0 0x40d312 in operator new[](unsigned long) /home/kcc/llvm/projects/compiler-rt/lib/asan/asan_new_delete.cc:46
    #1 0x417f1e in main example_UseAfterFree.cc:3
Shadow bytes around the buggy address:
  0x1c07c0003f30: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x1c07c0003f40: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x1c07c0003f50: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x1c07c0003f60: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x1c07c0003f70: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x1c07c0003f80: fa fa fa fa fa fa fa fa fa fa fa fa[fd]fd fd fd
  0x1c07c0003f90: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x1c07c0003fa0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x1c07c0003fb0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fa fa
  0x1c07c0003fc0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x1c07c0003fd0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
```

可以看到，=>指向的那行有一个byte数值用中括号给圈出来了：[fd]。它表示的是此次出错的内存地址对应的shadow memory的值。而其之前的fa表示Heap left redzone，它是之前该区域有效时的遗留产物。连续的fd总共有50个，每一个shadow memory的byte和8个normal memory byte对应，所以可以知道此次free的内存总共是50×8=400bytes。这一点在上面的log中也得到了验证，截取出来展示如下：

```shell
0x603e0001fc64 is located 4 bytes inside of 400-byte region [0x603e0001fc60,0x603e0001fdf0)
```

此外，ASAN的log中不仅有出错时的堆栈信息，还有该内存区域之前free时的堆栈信息。因此我们可以清楚地知道该区域是如何被释放的，从而快速定位问题，解决问题。

#### 1.3.2 Heap-Buffer-Overflow

想要检测HeapBufferOverflow的问题，只需要保证一点：

- 正常的Heap前后需要插入一定长度的安全区，而且此安全区对应的shadow memory需要被标记为特殊的状态。在ASAN的实现里，安全区被标记为0xfa。

测试代码：



![img](http://www.zyiz.net/upload/202004/01/202004012301235663.png)



ASAN输出的错误信息：

```shell
=================================================================
==1405==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0060bef84165 at pc 0x0058714bfb24 bp 0x007fdff09590 sp 0x007fdff09588
WRITE of size 1 at 0x0060bef84165 thread T0
    #0 0x58714bfb20  (/system/bin/bootanimation+0x8b20)
    #1 0x7b434cd994  (/apex/com.android.runtime/lib64/bionic/libc.so+0x7e994)
 
0x0060bef84165 is located 1 bytes to the right of 100-byte region [0x0060bef84100,0x0060bef84164)
allocated by thread T0 here:
    #0 0x7b4250a1a4  (/system/lib64/libclang_rt.asan-aarch64-android.so+0xc31a4)
    #1 0x58714bfac8  (/system/bin/bootanimation+0x8ac8)
    #2 0x7b434cd994  (/apex/com.android.runtime/lib64/bionic/libc.so+0x7e994)
    #3 0x58714bb04c  (/system/bin/bootanimation+0x404c)
    #4 0x7b45361b04  (/system/bin/bootanimation+0x54b04)
 
SUMMARY: AddressSanitizer: heap-buffer-overflow (/system/bin/bootanimation+0x8b20)
Shadow bytes around the buggy address:
  0x001c17df07d0: fa fa fa fa fa fa fa fa fd fd fd fd fd fd fd fd
  0x001c17df07e0: fd fd fd fd fd fa fa fa fa fa fa fa fa fa fa fa
  0x001c17df07f0: fd fd fd fd fd fd fd fd fd fd fd fd fd fa fa fa
  0x001c17df0800: fa fa fa fa fa fa fa fa fd fd fd fd fd fd fd fd
  0x001c17df0810: fd fd fd fd fd fa fa fa fa fa fa fa fa fa fa fa
=>0x001c17df0820: 00 00 00 00 00 00 00 00 00 00 00 00[04]fa fa fa
  0x001c17df0830: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x001c17df0840: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x001c17df0850: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x001c17df0860: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x001c17df0870: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
```

可以看到最终出错的shadow memory值为0x4，表示该shadow memroy对应的normal memory中只有前4个bytes是可寻址的。0x4的shadow memory前还有12个0x0，表示其前面的12个memory region（每个region有8个byte）都是完全可寻址的。因此所有可寻址的大小=12×8+4=100，正是代码中malloc的size。之所以此次访问会出错，是因为地址0x60bef84165意图访问最后一个region的第五个byte，而该region只有前四个byte可寻址。由于0x4后面是0xfa，因此此次错误属于HeapBufferOverflow。

### 1.4 缺陷

自从2011年诞生以来，ASAN已经成功地参与了众多大型项目，譬如Chrome和Android。虽然它的表现很突出，但仍然有些地方不尽如人意，重点表现在以下几点：

1. ASAN的运行是需要消耗memory和CPU资源的，此外它也会增加代码大小。它的性能相比于之前的工具确实有了质的提升，但仍然无法适用于某些压力测试场景，尤其是需要全局打开的时候。这一点在Android上尤为明显，每当我们想要全局打开ASAN调试某些奇葩问题时，系统总会因为负载过重而跑不起来。
2. ASAN对于UseAfterFree的检测依赖于隔离区，而隔离时间是非永久的。也就意味着已经free的区域过一段时间后又会重新被分配给其他人。当它被重新分配给其他人后，原先的持有者再次访问此块区域将不会报错。因为这一块区域的shadow memory不再是0xfd。所以这算是ASAN漏检的一种情况。
3. ASAN对于overflow的检测依赖于安全区，而安全区总归是有大小的。它可能是64bytes，128bytes或者其他什么值，但不管怎么样终归是有限的。如果某次踩踏跨过了安全区，踩踏到另一片可寻址的内存区域，ASAN同样不会报错。这是ASAN的另一种漏检。