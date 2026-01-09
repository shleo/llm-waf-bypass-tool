# LLM-WAF-Bypass-Tool

基于大语言模型(LLM)的智能渗透测试工具，能够动态探测和绕过 Web 应用防火墙(WAF)，支持完整的 HTTP 请求/响应可视化展示。

## 项目结构

```
.
├── vulnerable-lab/           # 漏洞靶场环境
│   ├── app.py               # Flask 应用 (含 SQL 注入漏洞和 WAF)
│   ├── waf_enhanced.py      # 增强 WAF 实现
│   └── templates/           # Web UI 模板
│       ├── pentest-ui-simple.html  # 渗透测试 UI
│       └── ...
│
├── tools/                   # 核心工具
│   ├── pentest_ui.py        # 渗透测试后端核心逻辑
│   ├── debug_json_parser.py # LLM JSON 响应解析调试工具
│   └── test_analyze_responses.py  # 响应分析测试脚本
│
├── llm_config.json.example  # LLM API 配置示例
└── README.md               # 项目文档
```

## 核心功能

### 1. LLM 驱动的 WAF 绕过
- **智能 Payload 生成**: 根据响应动态调整攻击策略
- **多种绕过技术**:
  - 内联注释: `UNION/**/SELECT`
  - 大小写混淆: `UnIoN SeLeCt`
  - 函数编码: `CHAR()` 函数
  - 双重编码
- **反思学习机制**: 失败后自动分析原因并调整策略
- **完整反馈循环**: 捕获 HTTP 状态码和 SQL 错误信息反馈给 LLM

### 2. Vulnerable Lab 靶场
- **多种 SQL 注入类型**: UNION 注入、错误注入、时间盲注
- **增强 WAF 防护**: 多层规则检测
- **WAF 控制端点**:
  - `/waf/stats` - 查看 WAF 统计
  - `/waf/toggle` - 开关 WAF
  - `/waf/mode/normal` - 普通模式
  - `/waf/mode/strict` - 严格模式

### 3. Web UI 界面
- **实时展示**: 测试过程实时可视化
- **HTTP 报文显示**: 完整的请求/响应报文展示
  - HTTP 请求详情：方法、URL、参数
  - HTTP 响应详情：状态码、响应体、数据预览
  - WAF 拦截状态和原因
- **LLM 分析可视化**: 显示模型思考过程和策略调整
- **响应分析**: 数据库类型识别、字段数量、SQL 错误分析

### 4. 增强的错误处理
- **类型安全**: 自动处理整数/字符串类型转换
- **调试日志**: 完整的数据类型和处理步骤日志
- **错误捕获**: 单项数据错误不影响整体流程

## 快速开始

### 1. 安装依赖

```bash
pip install -r vulnerable-lab/requirements.txt
```

### 2. 配置 LLM API

复制配置示例并编辑:
```bash
cp llm_config.json.example llm_config.json
```

编辑 `llm_config.json`:
```json
{
  "llm_provider": "openai",
  "api_key": "your-api-key",
  "model": "deepseek-chat",
  "base_url": "https://api.deepseek.com/v1/",
  "temperature": 0.7,
  "max_tokens": 3000
}
```

支持的 LLM 提供商:
- **DeepSeek**: `https://api.deepseek.com/v1/`
- **智谱 AI**: `https://open.bigmodel.cn/api/paas/v4/`
- **Ollama**: `http://localhost:11434/v1/`

### 3. 启动服务

#### 启动靶场服务
```bash
cd vulnerable-lab
python app.py
```

靶场运行在: `http://localhost:5000`

#### 启动渗透测试 UI
```bash
cd tools
python pentest_ui.py
```

UI 运行在: `http://localhost:5001`

### 4. 访问界面

打开浏览器访问 `http://localhost:5001`:
1. 输入目标地址 (如 `http://localhost:5000`)
2. 选择测试端点
3. 点击"开始测试"
4. 实时查看测试过程和 HTTP 报文

## 功能演示

### 场景: 绕过 UNION SELECT 检测

**WAF 规则**: 检测 `UNION SELECT` 模式

**绕过技术演进**:
```python
# 迭代 1: 原始 Payload (被阻止)
1' UNION SELECT 1,2,3

# 迭代 2: 内联注释 (被阻止)
1' UNION/**/SELECT 1,2,3

# 迭代 3: 大小写混淆 (成功)
1' UnIoN SeLeCt 1,2,3
```

### 错误反馈循环示例

```python
# 迭代 1: MySQL 特有函数 (500 错误)
1 UNION SELECT mysql_version(),2,3
# 响应: "no such function: mysql_version"
# LLM 学习: 检测到 SQLite 数据库

# 迭代 2: SQLite 函数 (成功)
1 UNION SELECT sqlite_version(),2,3
# 响应: {"data": ["3.39.2", null, null]}
```

## HTTP 通信可视化

前端展示每次探测的完整 HTTP 通信:

### 请求信息
- HTTP 方法 (GET/POST)
- 完整 URL
- 参数名和 Payload

### 响应信息
- HTTP 状态码
- 响应体 (success、data、error)
- SQL 查询语句
- 数据预览

### WAF 状态
- 拦截状态
- 拦截原因
- WAF 统计信息

## 技术栈

- **Python 3.8+**
- **Flask** - 靶场环境和 UI 后端
- **SQLAlchemy** - 数据库 ORM
- **SQLite** - 测试数据库
- **Requests** - HTTP 客户端
- **OpenAI API** - LLM 集成
- **Server-Sent Events (SSE)** - 实时推送

## 工具说明

### pentest_ui.py
渗透测试后端核心逻辑，实现:
- LLM Payload 生成和解析
- WAF 绕过迭代测试
- 反思学习机制
- HTTP 请求/响应分析
- SSE 实时事件推送

### debug_json_parser.py
LLM JSON 响应解析调试工具，用于测试和验证 LLM 返回的 JSON 解析逻辑。

### test_analyze_responses.py
响应分析测试脚本，验证各种数据类型的处理能力:
- 正常字典列表
- 整数列表
- 混合类型列表
- 500 错误响应
- 非 list 数据类型

## 安全说明

> **本工具仅用于授权的安全测试和教育目的**

- 禁止用于未授权的系统测试
- 测试前请确保获得明确的书面授权
- 所有测试活动应在隔离的测试环境中进行
- 发现的漏洞应负责任地披露

## 许可证

本项目仅供学习和研究使用。
