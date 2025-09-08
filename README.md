# MCP TDX SSE 服务器

## 功能概述

`mcp_server_sse_tdx.py` 实现了一个基于 Server-Sent Events (SSE) 的服务器应用，主要用于生成和认证 Intel Trust Domain Extensions (TDX) 引用数据。该服务器构建在 MCP 框架和 Starlette ASGI 框架之上，提供了两个核心工具接口用于获取和认证 TDX Quote 数据。

## 技术栈

- Python
- Starlette (ASGI 框架)
- Uvicorn (ASGI 服务器)
- requests (HTTP 客户端)
- base64 (数据编码/解码)
- json (JSON 数据处理)

## 工具接口设计

### 1. fetchQuote

**描述**: 获取 TDX Quote 引用数据

**参数**: 无

**返回**: JSON 格式数据，包含:
- `status`: 状态码 (200 表示成功)
- `quote_data`: Base64 编码的 TDX Quote 二进制数据
- `parse_result`: 解析后的 Quote 信息，包含 mr_td、rtmr 等字段

**实现**: 调用 `quote_generator.generate_quote()` 生成引用数据，将二进制数据转换为 Base64 编码字符串以便在 JSON 中传输。

### 2. attestQuote

**描述**: 对 TDX Quote 进行认证

**参数**: 
- `url` (必需): 认证服务的 URL 地址

**返回**: JSON 格式数据，包含:
- `status`: 状态码 (200 表示成功)
- `attest_result`: 认证结果

**实现流程**:
1. 调用 `quote_generator.generate_quote()` 获取 Quote 数据
2. 将二进制 Quote 数据转换为 Base64 编码字符串
3. 封装为 evidence 结构
4. 将 evidence 转换为 URL safe Base64 格式
5. 构建认证请求并发送到指定 URL
6. 解析并返回认证结果

### 3. fetchTdEventLog

**描述**: 获取 TDX 事件日志

**参数**: 无

**返回**: JSON 格式数据，包含:
- `status`: 状态码 (200 表示成功)
- `event_log_data`: Base64 编码的 TDX 事件日志二进制数据
- `event_log_count`: 事件日志条目数量

**实现**: 调用 `quote_generator.get_td_event_log()` 获取 TDX 事件日志数据，将二进制数据转换为 Base64 编码字符串以便在 JSON 中传输。

### 4. verifyUploadedQuote

**描述**: 验证客户端上传的 TDX Quote 文件

**参数**:
- `url` (必需): 认证服务的 URL 地址
- `quote_file` (必需): Base64 编码的 TDX Quote 文件内容

**返回**: JSON 格式数据，包含:
- `status`: 状态码 (200 表示成功)
- `verify_result`: 验证结果

**实现流程**:
1. 接收客户端上传的 Base64 编码 Quote 文件内容
2. 解码 Base64 数据获取原始 Quote 二进制数据
3. 封装为 evidence 结构
4. 将 evidence 转换为 URL safe Base64 格式
5. 构建认证请求并发送到指定 URL
6. 解析并返回验证结果

## 服务器端点

- `/sse`: SSE 连接端点，用于建立服务器与客户端之间的单向实时通信
- `/messages/`: POST 消息端点，用于处理客户端发送的消息

## 运行方式

服务器默认监听 `0.0.0.0:8800` 端口。启动服务器的代码如下:

```python
import uvicorn
uvicorn.run(starlette_app, host="0.0.0.0", port=8800)
```

## 依赖项

- 必需模块: anyio, click, httpx, mcp.types, starlette, requests, uvicorn
- 自定义模块: quote_generator (用于生成 TDX Quote 数据)

## 异常处理

- 导入 quote_generator 模块失败时会打印错误信息并抛出异常
- attestQuote 工具包含超时和连接错误处理
- 所有工具错误都会返回包含错误信息的 JSON 响应