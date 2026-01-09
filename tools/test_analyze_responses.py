#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for _analyze_responses method
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from pentest_ui import WAFBypassRunner


def test_analyze_responses():
    """Test the _analyze_responses method with various data types"""

    # 创建一个简单的 logger 用于测试
    class MockLogger:
        def __init__(self):
            self.events = []

        def log_step(self, step, data):
            self.events.append({'step': step, 'data': data})

    logger = MockLogger()
    waf = WAFBypassRunner('http://localhost:5000', logger)

    # 测试用例 1: 正常字典列表
    print("Test 1: Normal dict list")
    attempt_history_1 = [
        {
            'payload': '1 UNION SELECT 1,2,3',
            'technique': 'UNION Injection',
            'iteration': 1,
            'result': {
                'response': {
                    'data': [
                        {'id': 1, 'username': 'admin', 'password': 'pass123'},
                        {'id': 2, 'username': 'user', 'password': 'pass456'}
                    ]
                },
                'status_code': 200,
                'blocked': False
            },
            'waf_reason': '',
            'success': True
        }
    ]
    result = waf._analyze_responses(attempt_history_1)
    print(f"  database_type: {result['database_type']}")
    print(f"  field_count: {result['field_count']}")
    print(f"  extracted_info count: {len(result['extracted_info'])}")
    assert isinstance(result['field_count'], int), "field_count should be int"
    print("  PASS: Test 1 passed")

    # 测试用例 2: 包含整数的列表（可能出问题的情况）
    print("\nTest 2: List with integers (edge case)")
    attempt_history_2 = [
        {
            'payload': '1 UNION SELECT 1,2,3',
            'technique': 'UNION Injection',
            'iteration': 1,
            'result': {
                'response': {
                    'data': [1, 2, 3]  # 整数列表
                },
                'status_code': 200,
                'blocked': False
            },
            'waf_reason': '',
            'success': True
        }
    ]
    result = waf._analyze_responses(attempt_history_2)
    print(f"  database_type: {result['database_type']}")
    print(f"  field_count: {result['field_count']}")
    print(f"  extracted_info count: {len(result['extracted_info'])}")
    print("  PASS: Test 2 passed")

    # 测试用例 3: data 不是列表
    print("\nTest 3: data is not a list (edge case)")
    attempt_history_3 = [
        {
            'payload': '1 UNION SELECT 1,2,3',
            'technique': 'UNION Injection',
            'iteration': 1,
            'result': {
                'response': {
                    'data': 123  # 整数而不是列表
                },
                'status_code': 200,
                'blocked': False
            },
            'waf_reason': '',
            'success': True
        }
    ]
    result = waf._analyze_responses(attempt_history_3)
    print(f"  database_type: {result['database_type']}")
    print(f"  field_count: {result['field_count']}")
    print(f"  extracted_info count: {len(result['extracted_info'])}")
    print("  PASS: Test 3 passed")

    # 测试用例 4: 500 错误响应
    print("\nTest 4: 500 error with SQL error message")
    attempt_history_4 = [
        {
            'payload': '1 UNION SELECT sql,2,3',
            'technique': 'UNION Injection',
            'iteration': 1,
            'result': {
                'response': {
                    'success': False,
                    'error': 'no such function: sql',
                    'query': "SELECT * FROM user WHERE id = 1 UNION SELECT sql,2,3"
                },
                'status_code': 500,
                'blocked': False
            },
            'waf_reason': '',
            'success': False
        }
    ]
    result = waf._analyze_responses(attempt_history_4)
    print(f"  database_type: {result['database_type']}")
    print(f"  sql_errors count: {len(result['sql_errors'])}")
    print(f"  recent_errors count: {len(result['recent_errors'])}")
    assert result['database_type'] == 'SQLite', "Should detect SQLite from error"
    print("  PASS: Test 4 passed")

    # 测试用例 5: 混合类型列表
    print("\nTest 5: Mixed type list")
    attempt_history_5 = [
        {
            'payload': '1 UNION SELECT 1,2,3',
            'technique': 'UNION Injection',
            'iteration': 1,
            'result': {
                'response': {
                    'data': [
                        {'id': 1, 'username': 'admin'},
                        123,  # 混入整数
                        'string',  # 混入字符串
                        {'id': 2, 'username': 'user'}
                    ]
                },
                'status_code': 200,
                'blocked': False
            },
            'waf_reason': '',
            'success': True
        }
    ]
    result = waf._analyze_responses(attempt_history_5)
    print(f"  database_type: {result['database_type']}")
    print(f"  field_count: {result['field_count']}")
    print(f"  extracted_info count: {len(result['extracted_info'])}")
    print("  PASS: Test 5 passed")

    print("\n" + "="*60)
    print("All tests passed!")
    print("="*60)


if __name__ == '__main__':
    test_analyze_responses()
