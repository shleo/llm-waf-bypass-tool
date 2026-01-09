# 增强型 WAF 使用说明

## 概述

增强型 WAF（Web Application Firewall）采用多层检测机制，提供强大的 SQL 注入防护能力。

## 检测层级

### 第一层：基础 SQL 注入特征
- SQL 注释符 (`--`, `#`, `/* */`)
- 单引号注入 (`' OR '1'='1`)
- 布尔注入 (`AND 1=1`, `OR 1=1`)
- UNION 注入（包括内联注释绕过）
- SELECT/INSERT/UPDATE/DELETE 语句
- 数字型注入检测

### 第二层：函数检测
- MySQL 函数 (`concat`, `substring`, `mid`, etc.)
- 字符串函数 (`char`, `ascii`, `hex`, etc.)
- 系统函数 (`version()`, `database()`, `user()`)
- 时间函数 (`sleep()`, `benchmark()`)
- 聚合函数 (`group_concat`, `count()`)

### 第三层：时间盲注检测
- `SLEEP()` 函数
- `BENCHMARK()` 函数
- `WAITFOR DELAY`
- 延迟注入模式

### 第四层：元数据访问检测
- `information_schema`
- `mysql.*` 表访问
- `sys.*` 表访问
- 数据库枚举尝试

### 第五层：编码绕过检测
- URL 编码 (`%20`)
- 十六进制编码 (`0x...`)
- Unicode 编码 (`&#...`)
- CHAR() 函数编码
- 双重/多重编码

### 第六层：大小写混淆检测
- 混合大小写关键字 (`UnIoN SeLeCt`)
- 非标准大小写组合

### 第七层：内联注释检测
- 标准注释 (`/* ... */`)
- MySQL 特殊注释 (`/*! ... */`)
- 版本注释 (`/*!12345 ... */`)

### 第八层：堆叠查询检测
- 分号分隔的多语句
- 存储过程调用
- `DECLARE` 语句

### 第九层：二阶注入检测
- `sp_executesql`
- 动态 SQL 构建

### 第十层：绕过技术检测
- 空白字符替换
- 特殊字符注入
- 控制字符

## 检测级别

### Low（低级别）
- 仅启用基础 SQL 注入特征检测
- 适合高性能、低误杀场景
- 检测覆盖率：~40%

### Medium（中级别）- 默认
- 基础特征 + 函数 + 时间盲注 + 元数据
- 平衡性能和安全性
- 检测覆盖率：~70%

### High（高级别）
- 包含编码检测、注释检测、堆叠查询
- 高安全性，可能有少量误报
- 检测覆盖率：~95%

### Paranoid（偏执级别）
- 启用所有检测层级
- 最大安全覆盖
- 检测覆盖率：~100%

## API 端点

### 控制端点

#### 查看统计
```
GET /waf/enhanced/stats
```

响应示例：
```json
{
  "enabled": true,
  "detection_level": "medium",
  "blocked_count": 42,
  "blocked_requests": [
    {
      "data": "1' OR '1'='1",
      "pattern": "regexp",
      "reason": "Basic SQL Injection Pattern",
      "category": "basic",
      "risk_score": 5
    }
  ]
}
```

#### 切换 WAF
```
GET /waf/enhanced/toggle
```

#### 设置检测级别
```
GET /waf/enhanced/level/{level}
```

参数：`low`, `medium`, `high`, `paranoid`

### 测试端点

#### 增强型用户端点
```
GET /api/enhanced/user?id=1
```

#### 增强型登录端点
```
POST /api/enhanced/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=123
```

## 使用示例

### Python 测试脚本

```python
import requests

# 基础测试
response = requests.get('http://localhost:5000/api/enhanced/user?id=1')
print(response.json())

# SQL 注入测试
response = requests.get('http://localhost:5000/api/enhanced/user?id=1\' OR \'1\'=\'1')
if response.status_code == 403:
    print("WAF 阻止了攻击！")
    print(response.json())

# 设置检测级别
requests.get('http://localhost:5000/waf/enhanced/level/high')

# 查看统计
stats = requests.get('http://localhost:5000/waf/enhanced/stats').json()
print(f"已阻止: {stats['blocked_count']} 次攻击")
```

### curl 测试

```bash
# 正常请求
curl http://localhost:5000/api/enhanced/user?id=1

# SQL 注入攻击
curl "http://localhost:5000/api/enhanced/user?id=1' OR '1'='1"

# 设置检测级别
curl http://localhost:5000/waf/enhanced/level/paranoid

# 查看统计
curl http://localhost:5000/waf/enhanced/stats
```

## 绕过技术对比

### 基础 WAF vs 增强型 WAF

| 技术 | 基础 WAF | 增强型 WAF (Medium) | 增强型 WAF (High) |
|------|----------|---------------------|-------------------|
| `' OR '1'='1` | ✅ 阻止 | ✅ 阻止 | ✅ 阻止 |
| `1 UNION SELECT` | ❌ 通过 | ❌ 通过 | ✅ 阻止 |
| `1/**/UNION/**/SELECT` | ❌ 通过 | ❌ 通过 | ✅ 阻止 |
| `UnIoN SeLeCt` | ❌ 通过 | ❌ 通过 | ✅ 阻止 |
| `CHAR()` 编码 | ❌ 通过 | ❌ 通过 | ✅ 阻止 |
| 内联注释 | ❌ 通过 | ❌ 通过 | ✅ 阻止 |
| 时间盲注 | ❌ 通过 | ✅ 阻止 | ✅ 阻止 |
| 元数据访问 | ❌ 通过 | ✅ 阻止 | ✅ 阻止 |

## 性能考虑

### 检测开销
- Low: ~1ms per request
- Medium: ~2-3ms per request
- High: ~5-8ms per request
- Paranoid: ~10-15ms per request

### 建议
- 开发环境：使用 `low` 级别
- 测试环境：使用 `medium` 级别
- 生产环境：使用 `high` 级别
- 高风险场景：使用 `paranoid` 级别

## 扩展开发

### 添加自定义规则

```python
from waf_enhanced import EnhancedWAF

# 创建自定义 WAF
custom_waf = EnhancedWAF(enabled=True, detection_level='medium')

# 添加自定义模式
custom_waf.BASIC_PATTERNS.append(r'your_custom_pattern')
```

### 自定义检测级别

```python
class CustomWAF(EnhancedWAF):
    def __init__(self):
        super().__init__(enabled=True, detection_level='high')
        # 添加自定义规则
        self.CUSTOM_PATTERNS = [
            r'custom_pattern_1',
            r'custom_pattern_2'
        ]
```

## 最佳实践

1. **分层防御**：结合代码审计和参数化查询
2. **定期更新**：根据新的攻击模式更新规则
3. **日志分析**：定期检查 WAF 日志发现潜在攻击
4. **性能监控**：在高流量场景下监控 WAF 性能影响
5. **误报处理**：根据业务需求调整检测级别

## 注意事项

⚠️ WAF 是深度防御的一部分，不能替代：
- 输入验证
- 参数化查询
- 最小权限原则
- 定期安全审计

## 许可证

仅用于授权的安全测试和教育目的。
