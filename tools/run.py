#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AutoPentest - 统一启动入口

整合了所有功能的统一启动脚本，包括：
- SQL 注入检测
- LLM 智能分析
- 报告生成
"""
import sys
import os
import io

# 修复 Windows 控制台编码问题
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 添加项目根目录到 Python 路径
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'autopentest'))

import argparse
import json
import time
from datetime import datetime

# 导入 AutoPentest 核心组件
from autopentest.core import Requester, PoCRecorder
from autopentest.analyzers import SQLInjectionAnalyzer
from autopentest.reporters import JSONReporter, HTMLReporter
from autopentest.llm import LLMClient
from autopentest.config import Settings
from autopentest.utils import setup_logger


class AutoPentestRunner:
    """
    AutoPentest 统一运行器
    """

    def __init__(self, target: str, enable_llm: bool = True,
                 llm_config_path: str = "llm_config.json"):
        """
        初始化运行器

        Args:
            target: 目标 URL
            enable_llm: 是否启用 LLM
            llm_config_path: LLM 配置文件路径
        """
        self.target = target.rstrip('/')
        self.enable_llm = enable_llm
        self.llm_config_path = llm_config_path

        # 设置日志
        self.logger = setup_logger(level='INFO')

        # 初始化核心组件
        self.requester = Requester(timeout=10, max_retries=3)
        self.poc_recorder = PoCRecorder()

        # 初始化 LLM
        self.llm_client = None
        if self.enable_llm:
            self.llm_client = self._init_llm()

        # 初始化分析器
        self.analyzers = {
            'sqli': SQLInjectionAnalyzer(
                target=self.target,
                requester=self.requester,
                poc_recorder=self.poc_recorder,
                llm_client=self.llm_client,
                logger=self.logger
            )
        }

    def _init_llm(self):
        """初始化 LLM 客户端"""
        try:
            # 读取配置文件
            config_path = os.path.join(os.path.dirname(__file__), self.llm_config_path)
            if not os.path.exists(config_path):
                self.logger.warning(f"LLM config not found: {config_path}")
                return None

            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 移除注释字段
            if "_comment" in config:
                del config["_comment"]
            if "_comment_alternative_providers" in config:
                del config["_comment_alternative_providers"]

            # 检查 API Key
            if not config.get('api_key'):
                self.logger.warning("LLM API key not configured")
                return None

            # 创建 LLM 客户端
            llm_client = LLMClient(**config)
            self.logger.info(f"LLM initialized: {config.get('model', 'unknown')}")
            return llm_client

        except Exception as e:
            self.logger.warning(f"Failed to init LLM: {e}")
            return None

    def scan_endpoint(self, endpoint: str, method: str = 'GET',
                     params: dict = None, data: dict = None):
        """
        扫描端点

        Args:
            endpoint: 端点路径
            method: HTTP 方法
            params: URL 参数
            data: POST 数据
        """
        full_url = f"{self.target}{endpoint}"
        self.logger.info(f"Scanning: {full_url}")

        # 使用 SQL 注入分析器
        analyzer = self.analyzers['sqli']
        vulnerabilities = analyzer.analyze(
            endpoint=full_url,
            method=method,
            params=params,
            data=data
        )

        return vulnerabilities

    def scan_with_endpoints(self, endpoints: list):
        """扫描多个端点"""
        all_vulns = []

        for endpoint_info in endpoints:
            if isinstance(endpoint_info, str):
                endpoint = endpoint_info
                method = 'GET'
                params = None
                data = None
            else:
                endpoint = endpoint_info.get('path', '')
                method = endpoint_info.get('method', 'GET')
                params = endpoint_info.get('params')
                data = endpoint_info.get('data')

            try:
                vulns = self.scan_endpoint(endpoint, method, params, data)
                all_vulns.extend(vulns)
            except Exception as e:
                self.logger.error(f"Failed to scan {endpoint}: {e}")

        return all_vulns

    def generate_report(self, output_dir: str = ".", format: str = "both"):
        """
        生成报告

        Args:
            output_dir: 输出目录
            format: 报告格式 (json, html, both)
        """
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = self.target.replace('https://', '').replace('http://', '').replace('/', '_')

        reports = []

        if format in ('json', 'both'):
            json_path = os.path.join(output_dir, f'{domain}_{timestamp}.json')
            reporter = JSONReporter(self.poc_recorder)
            reporter.generate(json_path, self.target)
            reports.append(json_path)
            print(f"[+] JSON report: {json_path}")

        if format in ('html', 'both'):
            html_path = os.path.join(output_dir, f'{domain}_{timestamp}.html')
            reporter = HTMLReporter(self.poc_recorder)
            reporter.generate(html_path, self.target)
            reports.append(html_path)
            print(f"[+] HTML report: {html_path}")

        return reports

    def print_summary(self):
        """打印扫描摘要"""
        stats = self.poc_recorder.get_statistics()
        vulns = self.poc_recorder.get_all_vulnerabilities()

        print("\n" + "=" * 60)
        print("Scan Summary")
        print("=" * 60)
        print(f"\nTarget: {self.target}")
        print(f"LLM Enabled: {self.llm_client is not None}")
        if self.llm_client:
            print(f"LLM Model: {self.llm_client.model}")
        print(f"\nVulnerabilities Found: {stats['total']}")

        if stats.get('by_severity'):
            print("\nBy Severity:")
            for severity, count in stats['by_severity'].items():
                print(f"  {severity}: {count}")

        if stats.get('by_type'):
            print("\nBy Type:")
            for vtype, count in stats['by_type'].items():
                print(f"  {vtype}: {count}")

        if vulns:
            print("\nDetailed Findings:")
            for i, vuln in enumerate(vulns, 1):
                print(f"\n[{i}] {vuln.get('type', 'Unknown')}")
                print(f"    Endpoint: {vuln.get('endpoint', 'N/A')}")
                if vuln.get('parameter'):
                    print(f"    Parameter: {vuln['parameter']}")
                print(f"    Payload: {vuln.get('payload', 'N/A')}")
                print(f"    Severity: {vuln.get('severity', 'N/A')}")

    def cleanup(self):
        """清理资源"""
        self.requester.close()


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='AutoPentest - 统一渗透测试工具',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--target', '-t', required=True,
                       help='目标 URL (如: http://localhost:5000)')

    parser.add_argument('--endpoint', '-e',
                       help='要扫描的端点 (如: /api/user?id=1)')

    parser.add_argument('--test-all', action='store_true',
                       help='扫描所有常见测试端点')

    parser.add_argument('--no-llm', action='store_true',
                       help='禁用 LLM 分析')

    parser.add_argument('--llm-config', default='llm_config.json',
                       help='LLM 配置文件路径')

    parser.add_argument('--report-format', '-r',
                       choices=['json', 'html', 'both'],
                       default='both',
                       help='报告格式')

    parser.add_argument('--output-dir', '-o', default='.',
                       help='报告输出目录')

    args = parser.parse_args()

    print("=" * 60)
    print("AutoPentest - Automated Penetration Testing Tool")
    print("=" * 60)
    print(f"\nTarget: {args.target}")
    print(f"LLM: {'Disabled' if args.no_llm else 'Enabled'}")

    # 创建运行器
    runner = AutoPentestRunner(
        target=args.target,
        enable_llm=not args.no_llm,
        llm_config_path=args.llm_config
    )

    try:
        # 执行扫描
        if args.endpoint:
            # 扫描单个端点
            from urllib.parse import urlparse, parse_qs

            parsed = urlparse(args.endpoint)
            params = {}
            if parsed.query:
                for key, values in parse_qs(parsed.query).items():
                    params[key] = values[0] if values else ''

            runner.scan_endpoint(parsed.path, 'GET', params)

        elif args.test_all:
            # 扫描所有测试端点
            test_endpoints = [
                '/api/user?id=1',
                '/api/search?q=test',
                '/api/posts?id=1',
                {'path': '/login', 'method': 'POST',
                 'data': {'username': 'test', 'password': 'test'}}
            ]
            runner.scan_with_endpoints(test_endpoints)

        else:
            # 默认扫描
            test_endpoints = ['/api/user?id=1']
            runner.scan_with_endpoints(test_endpoints)

        # 打印摘要
        runner.print_summary()

        # 生成报告
        runner.generate_report(args.output_dir, args.report_format)

        print("\n" + "=" * 60)
        print("Scan completed successfully!")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        runner.cleanup()


if __name__ == '__main__':
    main()
