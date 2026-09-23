# bug-repro

各第三方组件 bug 的最小复现与证据归档。每个 bug 一个独立文件夹，内含复现源码、证据和修复补丁。

| 目录 | 组件 | 问题 | 状态 |
|---|---|---|---|
| [libslirp-sorecvfrom-hang](libslirp-sorecvfrom-hang/) | libslirp (≤4.9.4,QEMU user-mode 网络) | `sorecvfrom()` 在虚假可读事件下对阻塞 socket 调 `recvfrom()`，永久挂死调用线程（QEMU 中整机冻结） | 已复现，上游未修复，附 MSG_DONTWAIT 补丁 |
