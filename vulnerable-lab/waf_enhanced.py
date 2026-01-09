"""
增强型 WAF (Web Application Firewall)
提供更强的 SQL 注入防护能力
"""
import re
import html
from functools import wraps
from flask import request, jsonify
from urllib.parse import unquote


class EnhancedWAF:
    """
    增强型 WAF - 多层检测机制
    """

    # ========== 第一层：基础 SQL 注入特征 ==========
    BASIC_PATTERNS = [
        # SQL 注释符
        r"(--)|(#)|(/\*|\*/)|(;)",
        # 单引号注入 - 加强检测
        r"'\s*(or|and)\s+[\w\s'=<>]+[=<>]+[\w\s']*",
        # 布尔注入
        r"\b(or|and)\s+\d+\s*=\s*\d+",
        r"\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
        # UNION 注入（更严格）
        r"\bunion\s+(all\s+)?select\b",
        r"\bunion\s*/\*\s*(\d+)?\s*/\*\s*select\b",
        # SELECT 语句
        r"\bselect\s+.+?\bfrom\b",
        # 其他 SQL 关键字组合
        r"\b(insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
        r"\b(drop|alter|create)\s+(table|database|index)\b",
        #  EXEC/EXECUTE
        r"\b(exec|execute)\s*\(",
        # 检测单引号与特殊字符组合
        r"'.*\s+(or|and)\s+",
        # 检测数字型注入
        r"\d+\s*(or|and)\s+",
        # 检测等号两边的可疑内容
        r"=\s*['\"]?\d+['\"]?\s*(or|and)\b",
        # 检测常见绕过模式
        r"\bun\s*/\*\s*\w+\s*/\*\s*select\b",
    ]

    # ========== 第二层：函数和编码检测 ==========
    FUNCTION_PATTERNS = [
        # MySQL 函数
        r"\b(concat|group_concat|substring|substr|mid|left|right)\s*\(",
        r"\b(length|len|char|ascii|ord|hex|unhex)\s*\(",
        r"\b(version|database|user|current_user)\s*\(",
        r"\b(load_file|into\s+outfile)\s*\(",
        r"\b(benchmark|sleep|waitfor)\s*\(",
        r"\b(cast|convert)\s*\(",
        # 条件函数
        r"\b(if|case|when|then|else|end)\b",
        r"\b(ifnull|coalesce|nullif)\s*\(",
        # 字符串操作
        r"\b(trim|ltrim|rtrim|replace)\s*\(",
        r"\b(md5|sha1|sha2|encrypt)\s*\(",
    ]

    # ========== 第三层：时间盲注检测 ==========
    TIME_BASED_PATTERNS = [
        r"\bsleep\s*\(\s*\d+\s*\)",
        r"\bbenchmark\s*\(\s*\d+\s*,",
        r"\bwaitfor\s+delay\s+['\"]?\d+[:']?",
        r";\s*(declare|waitfor)\s+",
    ]

    # ========== 第四层：系统表和元数据 ==========
    METADATA_PATTERNS = [
        r"\binformation_schema\b",
        r"\bmysql\.",
        r"\bsys\.",
        r"\bpg_\w+",
        r"\bsys\.databases\b",
        r"\bsys\.objects\b",
        r"\bsys\.tables\b",
        r"\bsys\.columns\b",
    ]

    # ========== 第五层：编码绕过检测 ==========
    ENCODING_PATTERNS = [
        # CHAR() 编码
        r"\bchar\s*\(\s*\d+",
        r"\bchar\s*\(\s*\d+\s*,\s*\d+",
        # 十六进制编码
        r"0x[0-9a-f]+",
        r"\\x[0-9a-f]{2}",
        # URL 编码
        r"%[0-9a-f]{2}",
        # Unicode 编码
        r"%u[0-9a-f]{4}",
        r"&#\d+;",
        r"&#x[0-9a-f]+;",
        # 双重编码
        r"%25[0-9a-f]{2}",
    ]

    # ========== 第六层：大小写混淆检测 ==========
    def detect_case_obfuscation(self, text):
        """检测大小写混淆（关键字混合大小写）"""
        dangerous_keywords = [
            'union', 'select', 'insert', 'update', 'delete', 'drop',
            'exec', 'execute', 'script', 'javascript', 'onerror',
            'from', 'where', 'having', 'order', 'group'
        ]

        text_lower = text.lower()

        for keyword in dangerous_keywords:
            # 检查是否存在该关键字（忽略大小写）
            if keyword in text_lower:
                # 检查原始文本中是否有混合大小写
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                matches = pattern.findall(text)
                for match in matches:
                    # 如果匹配的文本不是全小写且不是关键字本身的大小写
                    if match != keyword and match != match.upper():
                        return True
        return False

    # ========== 第七层：内联注释检测 ==========
    INLINE_COMMENT_PATTERNS = [
        r"/\*.*?\*/",  # 标准注释
        r"/\*!.*?\*/",  # MySQL 特殊注释
        r"/\*!\d{5}.*?\*/",  # MySQL 版本注释
    ]

    # ========== 第八层：堆叠查询检测 ==========
    STACKED_QUERY_PATTERNS = [
        r";\s*(select|insert|update|delete|drop|alter|create)\b",
        r";\s*exec\s*\(",
        r";\s*declare\s+",
        r"\)\s*;\s*\d",
    ]

    # ========== 第九层：二阶注入检测 ==========
    SECOND_ORDER_PATTERNS = [
        # 存储过程调用
        r"\bsp_executesql\s*\(",
        r"\bexec\s*\(\s*@\w+",
        # 动态 SQL
        r"\bexec\s*\('",
        r"\bexecute\s*\('",
    ]

    # ========== 第十层：常用绕过技术检测 ==========
    EVASION_PATTERNS = [
        # 空白字符替换
        r"\s+/\*.*?\*/\s+",
        r"%20",  # URL 编码空格
        r"\+",
        # 特殊字符
        r"[<>\"'`]",
        r"[\x00-\x1F]",  # 控制字符
    ]

    def __init__(self, enabled=True, detection_level='medium'):
        """
        初始化增强型 WAF

        Args:
            enabled: 是否启用 WAF
            detection_level: 检测级别 (low/medium/high/paranoid)
        """
        self.enabled = enabled
        self.detection_level = detection_level
        self.blocked_count = 0
        self.blocked_requests = []

        # 根据检测级别设置规则
        self._setup_rules_by_level()

    def _setup_rules_by_level(self):
        """根据检测级别配置规则"""
        self.all_patterns = {
            'basic': self.BASIC_PATTERNS,
            'functions': self.FUNCTION_PATTERNS,
            'time_based': self.TIME_BASED_PATTERNS,
            'metadata': self.METADATA_PATTERNS,
            'encoding': self.ENCODING_PATTERNS,
            'inline_comment': self.INLINE_COMMENT_PATTERNS,
            'stacked_query': self.STACKED_QUERY_PATTERNS,
            'second_order': self.SECOND_ORDER_PATTERNS,
            'evasion': self.EVASION_PATTERNS,
        }

        # 根据级别选择启用的规则
        if self.detection_level == 'low':
            self.active_categories = ['basic']
        elif self.detection_level == 'medium':
            self.active_categories = ['basic', 'functions', 'time_based', 'metadata']
        elif self.detection_level == 'high':
            self.active_categories = ['basic', 'functions', 'time_based', 'metadata',
                                      'encoding', 'inline_comment', 'stacked_query']
        elif self.detection_level == 'paranoid':
            self.active_categories = list(self.all_patterns.keys())
        else:
            self.active_categories = ['basic', 'functions', 'time_based', 'metadata']

    def normalize_input(self, data):
        """标准化输入用于检测"""
        if not data:
            return ""

        # URL 解码
        try:
            data = unquote(str(data))
        except:
            pass

        # HTML 解码
        try:
            data = html.unescape(data)
        except:
            pass

        # 转为小写用于检测
        return data.lower()

    def check_request(self, request_data):
        """
        多层检测机制检查请求

        Returns:
            (is_blocked, reason, matched_pattern, category)
        """
        if not self.enabled:
            return False, None, None, None

        # 转换为字符串
        if isinstance(request_data, dict):
            check_values = []
            for v in request_data.values():
                check_values.append(str(v))
            check_string = ' '.join(check_values)
        else:
            check_string = str(request_data)

        # 标准化输入
        normalized = self.normalize_input(check_string)

        # 多层检测
        detection_results = []

        # 第一层：基础模式匹配
        if 'basic' in self.active_categories:
            for pattern in self.BASIC_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    detection_results.append({
                        'category': 'basic',
                        'pattern': pattern,
                        'reason': 'Basic SQL Injection Pattern'
                    })

        # 第二层：函数检测
        if 'functions' in self.active_categories:
            for pattern in self.FUNCTION_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    detection_results.append({
                        'category': 'functions',
                        'pattern': pattern,
                        'reason': 'SQL Function Detection'
                    })

        # 第三层：时间盲注
        if 'time_based' in self.active_categories:
            for pattern in self.TIME_BASED_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    detection_results.append({
                        'category': 'time_based',
                        'pattern': pattern,
                        'reason': 'Time-Based Injection Detected'
                    })

        # 第四层：元数据访问
        if 'metadata' in self.active_categories:
            for pattern in self.METADATA_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    detection_results.append({
                        'category': 'metadata',
                        'pattern': pattern,
                        'reason': 'Metadata Access Detected'
                    })

        # 第五层：编码检测
        if 'encoding' in self.active_categories:
            encoding_count = 0
            for pattern in self.ENCODING_PATTERNS:
                matches = re.findall(pattern, normalized, re.IGNORECASE)
                encoding_count += len(matches)

            # 如果有多个编码模式，可能是编码绕过
            if encoding_count >= 3:
                detection_results.append({
                    'category': 'encoding',
                    'pattern': 'multiple_encodings',
                    'reason': 'Encoding Evasion Attempt'
                })

        # 第六层：大小写混淆
        if 'evasion' in self.active_categories:
            if self.detect_case_obfuscation(normalized):
                detection_results.append({
                    'category': 'evasion',
                    'pattern': 'case_obfuscation',
                    'reason': 'Case Obfuscation Detected'
                })

        # 第七层：内联注释
        if 'inline_comment' in self.active_categories:
            for pattern in self.INLINE_COMMENT_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    detection_results.append({
                        'category': 'inline_comment',
                        'pattern': pattern,
                        'reason': 'Inline Comment Detected'
                    })

        # 第八层：堆叠查询
        if 'stacked_query' in self.active_categories:
            for pattern in self.STACKED_QUERY_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    detection_results.append({
                        'category': 'stacked_query',
                        'pattern': pattern,
                        'reason': 'Stacked Query Detected'
                    })

        # 第九层：二阶注入
        if 'second_order' in self.active_categories:
            for pattern in self.SECOND_ORDER_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    detection_results.append({
                        'category': 'second_order',
                        'pattern': pattern,
                        'reason': 'Second-Order Injection Detected'
                    })

        # 第十层：绕过技术
        if 'evasion' in self.active_categories:
            for pattern in self.EVASION_PATTERNS:
                if re.search(pattern, normalized, re.IGNORECASE):
                    detection_results.append({
                        'category': 'evasion',
                        'pattern': pattern,
                        'reason': 'Evasion Technique Detected'
                    })

        # 评估检测风险
        if detection_results:
            # 计算风险分数
            risk_score = len(detection_results)
            for result in detection_results:
                if result['category'] in ['time_based', 'metadata', 'stacked_query']:
                    risk_score += 2
                elif result['category'] in ['encoding', 'evasion']:
                    risk_score += 1

            # 根据检测级别调整阈值
            thresholds = {
                'low': 3,
                'medium': 2,
                'high': 1,
                'paranoid': 1
            }

            if risk_score >= thresholds.get(self.detection_level, 2):
                # 记录最严重的检测
                worst_result = detection_results[0]
                if len(detection_results) > 1:
                    # 找到最严重的类别
                    priority = ['time_based', 'stacked_query', 'metadata', 'functions', 'basic']
                    for p in priority:
                        for r in detection_results:
                            if r['category'] == p:
                                worst_result = r
                                break
                        if worst_result != detection_results[0]:
                            break

                self.blocked_count += 1
                self.blocked_requests.append({
                    'data': check_string[:200],
                    'pattern': worst_result['pattern'],
                    'reason': worst_result['reason'],
                    'category': worst_result['category'],
                    'risk_score': risk_score,
                    'detections_count': len(detection_results)
                })

                return True, worst_result['reason'], worst_result['pattern'], worst_result['category']

        return False, None, None, None

    def get_stats(self):
        """获取 WAF 统计信息"""
        return {
            'enabled': self.enabled,
            'detection_level': self.detection_level,
            'blocked_count': self.blocked_count,
            'blocked_requests': self.blocked_requests[-20:]  # 最近 20 条
        }


# 全局增强型 WAF 实例
enhanced_waf = EnhancedWAF(enabled=True, detection_level='medium')


def enhanced_waf_protect(param_name=None):
    """
    Flask 路由装饰器 - 增强型 WAF 保护

    Args:
        param_name: 要检查的参数名，None 表示检查所有参数
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not enhanced_waf.enabled:
                return f(*args, **kwargs)

            # 收集所有需要检查的数据
            check_data = {}

            # 检查 query 参数
            if request.args:
                check_data.update(request.args.to_dict())

            # 检查 POST 表单数据
            if request.form:
                check_data.update(request.form.to_dict())

            # 检查 JSON 数据
            if request.is_json:
                data = request.get_json()
                if isinstance(data, dict):
                    check_data.update(data)

            # 执行检查
            if check_data:
                # 如果指定了参数名，只检查该参数
                if param_name is not None:
                    check_data = {param_name: check_data.get(param_name, '')}

                for key, value in check_data.items():
                    blocked, reason, pattern, category = enhanced_waf.check_request(value)
                    if blocked:
                        return jsonify({
                            'success': False,
                            'error': f'WAF Blocked: {reason}',
                            'message': 'Request blocked by Enhanced Web Application Firewall',
                            'waf_stats': enhanced_waf.get_stats(),
                            'blocked_category': category,
                            'blocked_param': key
                        }), 403

            return f(*args, **kwargs)
        return wrapped
    return decorator


# ========== 便捷函数 ==========
def set_waf_level(level):
    """设置 WAF 检测级别"""
    global enhanced_waf
    enhanced_waf.detection_level = level
    enhanced_waf._setup_rules_by_level()


def toggle_waf(enabled=None):
    """切换 WAF 状态"""
    global enhanced_waf
    if enabled is not None:
        enhanced_waf.enabled = enabled
    else:
        enhanced_waf.enabled = not enhanced_waf.enabled
    return enhanced_waf.enabled
