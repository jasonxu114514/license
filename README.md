# license

一个面向 Linux 的最小授权下发系统。

它做的事情很简单：

1. client 提交 `license_key`、`device_id`、`arch`
2. server 校验授权，并把 `device_id` 绑定到该 key
3. server 按客户端架构生成一个 payload ELF
4. client 下载到内存并通过 memfd 直接执行
5. payload 启动后再次向 server 做运行时校验

---

## 目录

- `server.go`：服务端
- `client.go`：Linux client
- `payload.go`：可编辑的 payload 模板
- `go.mod`

---

## 当前特性

### 服务端

- `POST /verify`：授权校验并创建任务
- `GET /task/{task_id}`：获取任务元数据
- `GET /runtime/{task_id}`：payload 运行时校验
- `GET /download/{task_id}`：下载加密后的 ELF

### 客户端

- Linux only
- 自动生成并上传 `device_id`
- 自动上传运行架构：`amd64` / `arm64`
- 使用自定义 `User-Agent`
- 使用 memfd 执行，不落盘

### payload

- 有 5 分钟有效期
- 启动时重新计算本机 `device_id`
- 调用 `/runtime/{task_id}` 获取：
  - `license_key`
  - `sha256`
  - `server_time`
  - `expires_at`
- 重新计算自身 ELF 的 `sha256`
- 全部校验通过后才继续运行

### 传输层

- body 不直接传明文 JSON / 二进制
- 统一格式：
  - 先 `base64`
  - 再 `xor`
  - xor key = `sha256(UTC分钟字符串 YYYYMMDDHHmm)`
- 传输外层格式：

```text
LCX1:<YYYYMMDDHHmm>:<base64(xor(base64(payload)))>
```

---

## 数据库存储

SQLite 只存 `licenses` 表。

当前逻辑只使用这些字段：

- `license_key`：主键
- `last_seen_at`
- `last_seen_ip`
- `device_id`

也就是说：

- 授权 key 由你手工管理
- 首次成功验证时会绑定 `device_id`
- 后续不同 `device_id` 会被拒绝

任务本身不落库，只存在 server 进程内存里。

---

## Build

### server

```bash
go build -tags server -o server .
```

### client

```bash
go build -tags client -o client .
```

> 不要直接 `go build ./client.go`，请按包方式编译。

---

## 运行 server

```bash
./server
```

可选参数：

```bash
./server -listen :8080 -db ./app.db -go go -payload ./payload.go
```

参数说明：

- `-listen`：监听地址
- `-db`：SQLite 路径
- `-go`：Go 编译器路径
- `-payload`：payload 模板路径

---

## Server CLI

### 添加授权

```bash
./server add YOUR-LICENSE-KEY -db ./app.db
```

### 自动生成授权

```bash
./server add gen -db ./app.db
```

### 删除授权

```bash
./server del YOUR-LICENSE-KEY -db ./app.db
```

### 列出授权

```bash
./server list -db ./app.db
```

### 查看授权

```bash
./server show license YOUR-LICENSE-KEY -db ./app.db
```

---

## 运行 client

默认 server：

```go
const DefaultServerURL = "http://127.0.0.1:8080"
```

这些用法都支持：

```bash
./client
./client -key YOUR-LICENSE-KEY
./client -server http://127.0.0.1:8080
./client -server http://127.0.0.1:8080 -key YOUR-LICENSE-KEY
```

运行流程：

1. 输入或读取 `license_key`
2. 生成 `device_id`
3. 调用 `/verify`
4. 调用 `/task/{task_id}`
5. 调用 `/download/{task_id}`
6. 下载到内存
7. 通过 memfd 执行

---

## 首次初始化

没有 demo seed。

你需要先插入自己的授权：

```sql
INSERT INTO licenses (license_key)
VALUES ('YOUR-LICENSE-KEY');
```

---

## payload.go

`payload.go` 是模板文件，不直接参与正常构建。

server 每次创建任务时会：

1. 读取 `payload.go`
2. 替换模板占位符
3. 写到临时 `main.go`
4. 调 `go build`

当前会注入这些占位符：

- `__PAYLOAD_EXPIRES_AT_UNIX__`
- `__PAYLOAD_EXPIRED_MESSAGE__`
- `__PAYLOAD_LICENSE_KEY__`
- `__PAYLOAD_ARCH__`
- `__PAYLOAD_DEVICE_ID__`
- `__PAYLOAD_SERVER_URL__`
- `__PAYLOAD_TASK_ID__`
- `__PAYLOAD_USER_AGENT__`

如果你想改 payload 行为，直接改 `payload.go` 即可。

---

## 日志

server 默认会记录：

- 请求方法
- 路径
- IP
- HTTP 状态码
- 耗时

另外对 `/verify` 会额外记录：

- 验证通过
- 验证拒绝原因

示例：

```text
POST /verify ip=1.2.3.4 status=200 dur=500ms
verify ok ip=1.2.3.4 path=/verify task_id=20260407T010203-abcdef12
```

或：

```text
verify denied ip=1.2.3.4 path=/verify reason="device_id mismatch"
```

---

## 源站保护

server 默认拒绝“绕过 CDN 直接打源站”的请求：

- 如果请求没有 `X-Forwarded-For`
- 且也不是本地 `localhost / 127.0.0.1 / ::1`
- 就直接 `403 forbidden`

并记录：

```text
origin bypass rejected remote=... host=... method=... path=...
```

这意味着：

- 本地调试可以直接访问源站
- 生产环境建议经 CDN / 反代转发，并带上 `X-Forwarded-For`

---

## 注意事项

1. task 元数据只在内存中
   - server 重启后，旧 task 无法继续使用

2. payload 有 5 分钟有效期
   - 过期后会被 server 和 payload 双重拒绝

3. `device_id` 是强绑定
   - 首次绑定后，后续更换设备会失败

4. 当前传输层是轻量混淆
   - 不是强加密协议

5. 下载成功后，server 会删除生成的 ELF 文件
   - 但会短暂保留 task 内存信息供 `/runtime` 校验使用

---
