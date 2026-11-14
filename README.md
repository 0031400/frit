# frit

一个类似 frp 的极简 TCP 内网穿透工具，纯 Python 实现，自研对称加密。

## 特性

- TCP 单端口复用：服务端一个监听端口同时承载控制连接与数据连接。
- 客户端登录时上报 `proxies`，服务端为每个代理动态 `listen` 对外端口。
- 外部连接 -> 服务端分配 `taskId` -> 控制连接通知客户端 -> 客户端新建数据连接回连并回带 `taskId` -> 配对后双向转发。
- 自研加密中间件：PSK 派生固定 AES-128 key，AES-128-ECB + PKCS7；每条连接首帧解密并校验帧类型，非法即断开。
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

## 自测

```bash
uv run python selftest.py
```

启动本地 echo 服务 + frit server + frit client，验证小/大报文往返、以及错误 PSK 客户端被拒绝。

## 加密说明

- key = `SHA256(psk)[:16]`（AES-128）。
- 加密帧：`[2B 密文长度][AES-128-ECB 密文]`，PKCS7 padding。
- 明文帧：`[2B 随机帧类型] + 载荷`；`0x66F0`=控制 JSON，`0x04EB`=原始转发数据。
- 首帧解密后类型不合法即丢包断开（鉴权中间件）。

> 警告：固定 key 的 AES-ECB 存在相同明文块产生相同密文块的弱点，仅按需求提供最简可用实现，生产环境请改用 AES-GCM 等 AEAD 方案。
