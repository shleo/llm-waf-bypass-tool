# 工具说明

本目录包含可执行的测试工具脚本。

## 工具列表

### 1. waf_bypass.py
LLM 驱动的 WAF 绕过工具，能够根据 WAF 响应动态生成绕过 Payload。

**使用方法**:
```bash
python waf_bypass.py --target http://localhost:5000 --endpoint /api/protected/user --iterations 3
```

**功能**:
- 自动检测 WAF 是否启用
- 使用 LLM 生成测试 Payload
- 根据响应动态调整攻击策略
- 记录详细的攻击日志

### 2. test_waf_bypass.py
WAF 绕过测试的快速运行脚本。

**使用方法**:
```bash
python test_waf_bypass.py
```

**说明**: 使用预设参数直接运行测试，测试目标为 `http://localhost:5000/api/protected/user`

### 3. run.py
AutoPentest 框架的统一入口点。

**使用方法**:
```bash
python run.py --target http://localhost:5000 --endpoint /api/user --param id --value 1
```

**功能**:
- 扫描指定端点的 SQL 注入漏洞
- 集成 LLM 智能分析
- 生成详细的漏洞报告

## 参数说明

### waf_bypass.py 参数
- `--target, -t`: 目标服务器 (默认: http://localhost:5000)
- `--endpoint, -e`: 目标端点 (默认: /api/protected/user)
- `--param, -p`: 参数名 (默认: id)
- `--value, -v`: 参数值 (默认: 1)
- `--iterations, -i`: 最大迭代次数 (默认: 3)
- `--config, -c`: LLM 配置文件 (默认: llm_config.json)

### run.py 参数
- `--target, -t`: 目标服务器
- `--endpoint, -e`: 目标端点
- `--param, -p`: 参数名
- `--value, -v`: 参数值
- `--config, -c`: LLM 配置文件

## 输出文件

测试完成后，报告保存在 `../reports/` 目录:
- `attack_log.json` - 详细的攻击日志
- `waf_bypass_report.json` - WAF 绕过测试报告
- `vulnerability_report.json` - 漏洞扫描报告
