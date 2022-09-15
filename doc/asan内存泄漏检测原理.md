很多同学对ASAN内存泄漏的基本原理并不是很了解,如果仅仅只是出了一些一眼就能看出来的泄漏问题还好,如果ASAN泄漏的报告缺少一些信息,比如说堆栈,不是很懂原理的同学就很容易抓瞎,一些问题就查不下去了.因此个人觉得还是很有必要简单普及一下ASAN泄漏的基本原理.

## 基本原理

**ASAN内存泄漏检测原理如下：**

1. ASAN会接管内存申请接口，即用户的内存全都由ASAN来管理；

2. 当**进程退出时触发ASAN内存泄漏检测**，开发可以使用复位单板、重启设备等一切可以让进程正常退出的方法来触发ASAN进行内存泄漏检测；

3. 开始内存泄漏检查后，ASAN会遍历当前所有已经分配给用户但没有释放的堆内存，扫描这些内存是否被某个指针引用着，这些指针可能是全局变量、局部变量或者是堆内存里面的指针，如果没有则认为是泄漏了；如果内存被引用着，比如内存申请完后放在V8的Local数据区、插树、插链表等，是不会报泄漏的；

4. 将所有泄漏的内存信息打出来，包含内存大小和内存申请的调用栈信息；

因此，如果日志中报内存泄漏了，**开发同学需要分析该内存申请的指针是存放到哪儿的，在流程中这个指针是在哪儿被改了，但是没有释放内存**。

讲一个会导致内存泄漏的场景，某基础模块发现4个内存泄漏问题，都是内存申请后存放到全局变量中，开发说该内存会一直使用不释放，不算泄漏，但实际上该全局变量会被初始化两次，第二次没有判断全局变量是否已经初始化，而直接赋成新的内存指针值，导致泄漏。

## 误报

**已知ASAN内存泄漏误报场景：**

1. 结构体非4字节对齐：例如报结构体A内存泄漏，且A内存的指针存放在结构体B中，由于ASAN扫描内存时是按4字节偏移进行的，所以如果A指针在结构体B中的偏移非4的整数倍，ASAN就扫不到，出现误报（主干要求：非4字节对齐的结构体需要整改）；

2. 信号栈内存：该内存是在信号处理函数执行时做栈内存用的，其指针会保存到内核中，所以ASAN扫描不到，产生误报；

3. 内存指针偏移后保存：有子系统代码实现比较特殊，将申请的内存指针做一个很大的偏移（超过该内存的合法范围）操作后保存起来，通过偏移后的值ASAN根本找不到对应的内存，所以误报泄漏；

4. 存在ASAN未监控的内存接口。

## 例子

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

int main()
{
        char *db_name = "/wns/etc/config/db/sw_data.db";
        char *sql = "select branch_id from ap_info where ap_id=1007550544";
        int rc = 0;
        sqlite3 *db = NULL;
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_open(db_name, &db);
        rc = sqlite3_prepare(db, sql, strlen(sql), &stmt, NULL);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
                fprintf(stderr, "sql error: %s\n", sqlite3_errmsg(db));
                return -1;
        }
        sqlite3_reset(stmt);
        return 0;
}
```

我们知道,上面的代码跑过一轮之后,ASAN肯定会报内存泄漏:

```shell
=================================================================
==16050==ERROR: LeakSanitizer: detected memory leaks

Indirect leak of 285216 byte(s) in 3023 object(s) allocated from:
    #0 0x7ffff72bf82f in __interceptor_malloc ../../../../gcc-10.2.0/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0x7ffff47fa6f7  (/wns/3party/lib/libsqlite3.so.0+0x2f6f7)

Indirect leak of 37248 byte(s) in 31 object(s) allocated from:
    #0 0x7ffff72bfb98 in __interceptor_realloc ../../../../gcc-10.2.0/libsanitizer/asan/asan_malloc_linux.cpp:164
    #1 0x7ffff47fa68f  (/wns/3party/lib/libsqlite3.so.0+0x2f68f)

SUMMARY: AddressSanitizer: 322544 byte(s) leaked in 3055 allocation(s).
```

但是下面的代码会报吗?

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

sqlite3 *db = NULL;
sqlite3_stmt *stmt = NULL;

int main()
{
        char *db_name = "/wns/etc/config/db/sw_data.db";
        char *sql = "select branch_id from ap_info where ap_id=1007550544";
        int rc = 0;
        rc = sqlite3_open(db_name, &db);
        rc = sqlite3_prepare(db, sql, strlen(sql), &stmt, NULL);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
                fprintf(stderr, "sql error: %s\n", sqlite3_errmsg(db));
                return -1;
        }
        sqlite3_reset(stmt);
        return 0
}
```

估计有不少同学认为会报，事实上，不会报.注意上面的检测原则，**只要被分配的内存被引用,也就是某个变量持有内存块的指针值, 而且变量为全局变量/静态变量(不包括栈变量),或者为可以通过全局变量/静态变量到达的堆变量(可能要经历多次才能到达),ASAN就认为这块内存还有引用,不算泄漏**。

你可能很好奇这个ASAN是怎么实现的,其实非常简单粗暴:

1. 所有的内存分配都有记录，每次分配出的一块内存,ASAN称之为chunk，ASAN有对应的metadata来记录这个chunk的状态，包括内存块大小,内存状态(kReachable,kDirectlyLeaked ...)等。我们可以通过某一个地址,确定地址对应的chunk；
2. 内存泄漏检测的时候，ASAN没有什么技巧,直接扫描,从全局变量,静态变量所在的区域开始扫描,N个字节(指针所占字节数,在64位系统下,N为8)为一组,将其强制转换为地址,我们假定其为A,如果通过A可以找到chunk B,那么就将chunk B标记为kReachable(当然实际情况会更加复杂一些,还要考虑对齐等因素), 将chunk B加入扫描队列(注意去重)；
3. 其余的过程类似于BFS，直到将所有可达的内存块标记为kReachable；
4. 自然,不可达的就泄漏了。

有兴趣的可以去翻一下代码。

所以，**所有被ASAN爆出来的泄漏,肯定是那些无法通过指针访问到的内存块**。