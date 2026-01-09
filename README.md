# AutoPentest - LLM 驱动的自动化渗透测试工具

基于大语言模型(LLM)的智能渗透测试工具，能够动态探测和绕过 Web 应用防火墙(WAF)。

## 项目结构

```
test/
├── autopentest/          # 核心渗透测试框架
│   ├── analyzers/        # 漏洞分析器 (SQL注入等)
│   ├── core/            # 核心模块 (请求器、扫描器基类、POC记录)
│   └── llm/             # LLM 集成 (客户端、提示词模板)
│
├── vulnerable-lab/       # 漏洞靶场环境
│   ├── app.py           # Flask 应用 (含 SQL 注入漏洞和 WAF)
│   ├── waf.py           # WAF 实现
│   └── templates/       # Web UI 模板
│
├── tools/               # 工具脚本
│   ├── waf_bypass.py    # LLM 驱动的 WAF 绕过工具
│   └── run.py           # 统一入口点
│
├── reports/             # 测试报告目录
└── llm_config.json      # LLM API 配置
```

## 核心功能

### 1. LLM 驱动的 WAF 绕过
- **智能 Payload 生成**: 根据响应动态调整攻击策略
- **多种绕过技术**:
  - 内联注释: `UNION/**/SELECT`
  - 大小写混淆: `UnIoN SeLeCt`
  - 函数编码: `CHAR()` 函数
  - 双重编码
- **详细日志记录**: 完整记录每次 LLM 交互和测试结果

### 2. Vulnerable Lab 靶场
- **多种 SQL 注入类型**: GET 注入、登录注入、搜索注入、时间盲注
- **WAF 防护层**: 可配置的 WAF 规则
- **WAF 控制端点**:
  - `/waf/stats` - 查看 WAF 统计
  - `/waf/toggle` - 开关 WAF
  - `/waf/mode/normal` - 普通模式
  - `/waf/mode/strict` - 严格模式

### 3. Web UI 界面
- **实时展示**: 测试过程实时可视化
- **HTTP 报文显示**: 完整的请求/响应报文展示
- **LLM 分析可视化**: 显示模型思考过程和策略调整

## 快速开始

### 1. 安装依赖

```bash
pip install -r vulnerable-lab/requirements.txt
```

### 2. 配置 LLM API

编辑 `llm_config.json`:
```json
{
  "llm_provider": "openai",
  "api_key": "your-api-key",
  "model": "glm-4-flash",
  "base_url": "https://open.bigmodel.cn/api/paas/v4/"
}
```

支持的 LLM 提供商:
- **Zhipu (智谱)**: `https://open.bigmodel.cn/api/paas/v4/`
- **DeepSeek**: `https://api.deepseek.com/v1/`
- **Ollama**: `http://localhost:11434/v1/`

### 3. 启动服务

#### 启动靶场服务
```bash
cd vulnerable-lab
python app.py
```

靶场运行在: `http://localhost:5000`

#### 启动 Web UI
```bash
cd tools
python pentest_backend_simple.py
```

UI 运行在: `http://localhost:5001`

### 4. 访问界面

打开浏览器访问 `http://localhost:5001`:
- 输入目标地址 (如 `http://localhost:5000`)
- 选择测试端点
- 点击"开始测试"
- 实时查看测试过程和 HTTP 报文

## 使用示例

### 命令行 WAF 绕过测试

```bash
python tools/waf_bypass.py
```

### 查看测试报告

测试完成后，报告保存在 `reports/` 目录

## WAF 绕过演示

### 场景: 绕过 UNION SELECT 检测

**WAF 规则**: 检测 `UNION SELECT` 模式

**绕过技术**: 内联注释

```python
# 原始 Payload (被阻止)
1' UNION SELECT 1,2,3,4,5,6

# 绕过 Payload (成功)
1 UNION/**/SELECT 1,2,3,4,5,6
```

## 安全说明

⚠️ **本工具仅用于授权的安全测试和教育目的**

- 禁止用于未授权的系统测试
- 测试前请确保获得明确的书面授权
- 所有测试活动应在隔离的测试环境中进行
- 发现的漏洞应负责任地披露

## 技术栈

- **Python 3.8+**
- **Flask** - 靶场环境
- **SQLAlchemy** - 数据库 ORM
- **SQLite** - 测试数据库
- **Requests** - HTTP 客户端
- **OpenAI API** - LLM 集成

## 扩展开发

### 添加新的漏洞分析器

```python
from autopentest.core.base_scanner import BaseScanner

class CustomAnalyzer(BaseAnalyzer):
    def scan(self):
        # 实现扫描逻辑
        pass
```

## 许可证

本项目仅供学习和研究使用。
