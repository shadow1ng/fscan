# 使用说明

本模块分为两部分：**RPC 调用** 和 **MCP 调用**。

## 启动方式

### 1. RPC 调用

运行以下命令启动 RPC 服务：

```bash
go run remote.go -api 127.0.0.1:8080 -sercet xxxx
```

- `-api`：指定监听地址和端口。
- `-sercet`：指定访问密钥。

### 2. MCP 调用

直接运行：

```bash
go run remote.go
```

- 默认使用 `stdio` 协议。
- 如需指定使用 `sse` 协议，请添加 `-transport sse` 参数：

```bash
go run remote.go -transport sse
```

## 开发调试

在开发 MCP 时，可以借助 [Model Context Protocol Inspector](https://www.npmjs.com/package/@modelcontextprotocol/inspector) 进行调试。

使用以下命令启动调试器：

```bash
npx @modelcontextprotocol/inspector
```

启动后即可在终端中进行调试。


