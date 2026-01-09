#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
直接运行 WAF 绕过测试脚本
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_waf_bypass import LLMWAFBypass

# 直接指定参数
tool = LLMWAFBypass(
    llm_config_path="llm_config.json",
    target="http://localhost:5000"
)

result = tool.bypass_waf(
    endpoint="/api/protected/user",
    param_name="id",
    param_value="1",
    max_iterations=3
)

tool.print_summary()
tool.logger.save()

print("\n[+] 测试完成")
