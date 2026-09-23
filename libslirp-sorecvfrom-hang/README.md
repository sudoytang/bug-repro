# libslirp sorecvfrom 阻塞 recvfrom 挂死 — 最小复现

在生产 VPS(QEMU + KVM）环境里抓到的一种 guest 整机"假死":guest 内核无任何日志、QEMU 0% CPU、虚拟机时间像被冻结。根因定位到 **libslirp 的 `sorecvfrom()` 在没有数据可读时对阻塞 socket 调用 `recvfrom()`，永久卡死 QEMU 主循环线程（持 BQL 大锁）→ vCPU 线程全部死等 → 整机冻结**。

上游（截至 2026-09 最新发布版 4.9.4）**从未修复**此问题，公开 CVE/changelog 中也没有记录。

## Bug 机制

`slirp_pollfds_poll()` 对任何 revents 含 `IN|HUP|ERR` 的 UDP socket 无条件调用 `sorecvfrom()`，而后者：

1. 不检查 `FIONREAD` 返回的待收字节数是否为 0;
2. `recvfrom()` 不带 `MSG_DONTWAIT`;
3. `udp_attach()` 创建的 host socket 是阻塞模式（`slirp_socket()` 只加 `SOCK_CLOEXEC`)。

三条凑齐：只要 poll 出现"虚假可读"（如 POLLERR 但错误队列已被 MSG_ERRQUEUE 读空、或 pollfds_idx 与 fd 错位）,`recvfrom` 就永远阻塞。在 QEMU 里这发生在持 BQL 的主循环线程上，于是整台 VM 冻结。

## 最小复现（约 180 行 C，无 QEMU，确定性 100%)

`slirp_repro.c` 直接链接 libslirp:

1. `slirp_input()` 注入伪造的 guest→外网 UDP 报文 → `udp_attach()` 创建阻塞 host socket（等价于 guest 里 DNS/NTP 流量触发的效果）;
2. 用 `get_revents` 回调谎报"socket 可读"（复现野外的虚假可读瞬间）;
3. `sorecvfrom()` → 阻塞 `recvfrom()` → 挂死。

### 编译

```bash
# 需要 libslirp-dev(复现用的是 Ubuntu 4.7.0-1ubuntu3.1)和 libglib2.0-dev
gcc -O0 -g slirp_repro.c -o slirp_repro $(pkg-config --cflags --libs glib-2.0) -lslirp
```

### 运行

```bash
./slirp_repro honest   # 对照组:不谎报,立即返回,rc=0
./slirp_repro lie      # 复现组:永久挂死(用 timeout 5 ./slirp_repro lie 观察 rc=124)
```

### 验证挂死点就是 recvfrom

挂死时另开终端 `gdb -p <pid> -batch -ex bt`，栈与生产环境挂死的 QEMU 逐帧一致（libslirp 内部偏移都相同）:

```text
#0 __libc_recvfrom(fd=3, len=1500, flags=0)
#1 libslirp.so.0 +0x1c3        <- sorecvfrom 内联
#2 slirp_pollfds_poll + 564
```

### 在线"复活"

找到该进程的 UDP 端口（`/proc/<pid>/net/udp`)，向 `127.0.0.1:<port>` 注入 1 字节 UDP,`recvfrom` 立即返回、进程正常退出 rc=0——同一招在生产容器里救活过被冻结的 guest(ping/ssh 3 秒内恢复）。

## 修复

`libslirp-4.7.0-sorecvfrom-dontwait.patch`:`sorecvfrom()` 的 `recvfrom` 加 `MSG_DONTWAIT`(FIONREAD==0 时直接 return 或 udp_attach 设 O_NONBLOCK 亦可）。同版本源码打补丁重编替换 `libslirp.so.0` 即可，QEMU 动态链接无需重编。

注意：上游 4.9.4 的 `udp_attach`/`sorecvfrom`/`slirp_socket` 与 4.7.0 逐字节一致，**升级版本无法解决，必须自己 patch**；也适合拿本 repro 给上游 freedesktop/libslirp 报 issue。

## 证据文件

| 文件 | 内容 |
|---|---|
| `evidence/repro-hang-bt.txt` | 本 repro 挂死时的 gdb 栈 + socket 状态（无 O_NONBLOCK、rx_queue=0) |
| `evidence/repro-inject-rescue.txt` | 注入 1 字节后进程恢复并正常退出的记录 |
| `evidence/qemu9540-all-threads-bt.txt` | 生产环境中招的 QEMU 全线程栈：两 vCPU 死等 BQL，主线程卡在同一 libslirp recvfrom(`bql.__data.__owner` = 主线程 LWP) |
