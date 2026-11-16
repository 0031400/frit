# frit

一个类似 frp 的极简 TCP 内网穿透工具，纯 Python 实现，自研对称加密。

## 特性

- TCP 单端口复用：服务端一个监听端口同时承载控制连接与数据连接。
- 客户端登录时上报 `proxies`，服务端为每个代理动态 `listen` 对外端口。
- 外部连接 -> 服务端分配 `taskId` -> 控制连接通知客户端 -> 客户端新建数据连接回连并回带 `taskId` -> 配对后双向转发。
- 自研加密中间件：PSK 派生固定 AES-128 key，AES-128-ECB + PKCS7；每条连接首帧解密并校验帧类型，非法即断开。
- 控制连接心跳：服务端每 60s（±10%）ping 一次，5s 内没有 pong 就判定 client 失联，删除该 client 并关闭它的对外监听端口，外部连接随即快速失败；外部连接 5s 内等不到配对也会立即断开并 ping 一次确认 client 是否还活着。
- 明文帧头为两个随机生成的 16-bit 类型码（硬编码，非 1/2）。
- 配置仅从命令行 `-c` 指定文件读取，不读任何环境变量。

## 安装

```bash
uv sync
```

## 配置

`data/server.json`
```json
{
    "listen": "tcp://0.0.0.0:40000",
    "psk": "bP2T43nYNCBpeWYbjr5C",
    "debug": false
}
```

`data/client.json`
```json
{
    "server": "tcp://127.0.0.1:40000",
    "psk": "bP2T43nYNCBpeWYbjr5C",
    "name": "desktop",
    "debug": false,
    "proxies": [
        {
            "name": "http1",
            "localIP": "127.0.0.1",
            "localPort": 8000,
            "remoteIP": "0.0.0.0",
            "remotePort": 8000
        }
    ]
}
```

- `psk` 两端必须一致。
- `debug: true` 输出 DEBUG 日志，`false` 仅 INFO 及以上。
- 代理字段：`localIP/localPort` 为内网真实服务，`remoteIP/remotePort` 为服务端对外暴露的监听地址。

## 运行

```bash
uv run frit server -c data/server.json
uv run frit client -c data/client.json
```

`-c` 省略时默认读取当前目录的 `config.json`。

## 心跳与失联处理

- 服务端每 60s（±10% 抖动）在控制连接上发 `ping{id}`，client 立刻回 `pong{id}`。
- 5s 内没收到 pong → 判定 client 失联：关闭控制连接、关闭它所有对外监听端口、释放 client 名字（同名 client 可立刻重新登录）。
- 外部连接进来后 5s 内没等到 client 的数据连接（`connectRes`）→ 立即断开这条外部连接，并 ping 一次：回 pong 说明 client 只是这一单慢，不回则在 5s 后按失联处理。
- 探测进行期间（`suspect`），新外部连接直接拒绝，不再逐条等超时。
- client 侧：控制连接 150s 收不到任何消息就主动断开，2s 后重连；连服务端/数据连接/本地服务的超时分别是 10s / 3s / 2s，保证能在服务端 5s 配对超时之前给出结果。

## 加密说明

- key = `SHA256(psk)[:16]`（AES-128）。
- 加密帧：`[2B 密文长度][AES-128-ECB 密文]`，PKCS7 padding。
- 明文帧：`[2B 随机帧类型] + 载荷`；`0x66F0`=控制 JSON，`0x04EB`=原始转发数据。
- 首帧解密后类型不合法即丢包断开（鉴权中间件）。

> 警告：固定 key 的 AES-ECB 存在相同明文块产生相同密文块的弱点，仅按需求提供最简可用实现，生产环境请改用 AES-GCM 等 AEAD 方案。
