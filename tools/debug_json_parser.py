#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM JSON Response Parser Debug Tool

For testing and debugging LLM returned JSON parsing logic
"""

import re
import json
import sys


def parse_llm_response(llm_response):
    """Parse LLM response and extract JSON"""

    print(f"\n{'='*60}")
    print(f"Raw response length: {len(llm_response)} chars")
    print(f"Raw response first 100 chars: {llm_response[:100]}")
    print(f"{'='*60}\n")

    # Try multiple methods to extract JSON
    json_match = None
    json_str = None

    # Method 1: Find complete JSON with payload, technique, explanation
    print("Method 1: Exact match pattern")
    pattern = r'\{\s*"payload"\s*:\s*"[^"]*"\s*,\s*"technique"\s*:\s*"[^"]*"\s*,\s*"explanation"\s*:\s*"[^"]*"(?:\s*,\s*"stage"\s*:\s*"[^"]*")?\s*\}'
    json_match = re.search(pattern, llm_response, re.DOTALL)
    if json_match:
        print(f"OK Method 1 success! Matched: {json_match.group(0)[:100]}...")
    else:
        print("X Method 1 failed")

    # Method 2: Find any { ... } structure JSON
    if not json_match:
        print("\nMethod 2: Brace counting")
        brace_count = 0
        start_idx = -1
        for i, char in enumerate(llm_response):
            if char == '{':
                if brace_count == 0:
                    start_idx = i
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and start_idx >= 0:
                    json_str = llm_response[start_idx:i+1]
                    print(f"OK Method 2 found JSON block: start {start_idx}, end {i}")
                    print(f"JSON content: {json_str[:100]}...")

                    # Verify contains required fields
                    if 'payload' in json_str and 'technique' in json_str:
                        json_match = type('obj', (object,), {'group': lambda self: json_str})()
                        print("OK Method 2 validation passed, contains required fields")
                    else:
                        print(f"X Method 2 validation failed: payload={('payload' in json_str)}, technique={('technique' in json_str)}")
                    break

        if not json_str:
            print("X Method 2 failed: no matching brace pair found")

    # Method 3: Try simple regex match as last resort
    if not json_match:
        print("\nMethod 3: Simple regex match")
        json_match = re.search(r'\{.*?\}', llm_response, re.DOTALL)
        if json_match:
            print(f"OK Method 3 success! Matched: {json_match.group(0)[:100]}...")
        else:
            print("X Method 3 failed")

    # Summary
    if not json_match:
        print(f"\nX All methods failed!")
        print(f"Contains '{{' and '}}': {'{' in llm_response and '}' in llm_response}")
        print(f"Contains 'payload': {'payload' in llm_response}")
        print(f"Contains 'technique': {'technique' in llm_response}")
        print(f"Contains 'explanation': {'explanation' in llm_response}")
        return None

    # Try to parse JSON
    try:
        extracted_json = json_match.group(0)
        print(f"\nExtracted JSON: {extracted_json}")

        llm_data = json.loads(extracted_json)
        print(f"\nOK JSON parsing successful!")
        print(f"  - payload: {llm_data.get('payload', '')[:50]}...")
        print(f"  - technique: {llm_data.get('technique', 'Unknown')}")
        print(f"  - explanation: {llm_data.get('explanation', '')[:50]}...")

        return llm_data

    except json.JSONDecodeError as e:
        print(f"\nX JSON parsing failed: {e}")
        print(f"  Error position: {e.pos}")
        print(f"  Extracted content: {extracted_json[:200]}")
        return None


# Test cases
test_cases = [
    # Standard format
    '''{"payload": "1 UNION SELECT 1,2,3", "technique": "UNION Injection", "explanation": "Basic injection"}''',

    # With newlines and spaces
    '''{
        "payload": "1 UNION SELECT 1,2,3",
        "technique": "UNION Injection",
        "explanation": "Basic injection"
    }''',

    # With extra text
    '''OK, here is my suggestion:

{"payload": "1 UNION SELECT 1,2,3", "technique": "UNION Injection", "explanation": "Basic injection"}

Hope this helps.''',

    # JSON array
    '''[{"payload": "1 UNION SELECT 1,2,3", "technique": "UNION Injection", "explanation": "Basic injection"}]''',

    # Markdown code block
    '''Here is the payload:

```json
{"payload": "1 UNION SELECT 1,2,3", "technique": "UNION Injection", "explanation": "Basic injection"}
```

''',
]


if __name__ == "__main__":
    print("LLM JSON Parser Debug Tool")
    print("=" * 60)

    for i, test in enumerate(test_cases, 1):
        print(f"\n\n{'#' * 60}")
        print(f"# Test Case {i}")
        print(f"{'#' * 60}")
        result = parse_llm_response(test)

        if result:
            print(f"\nSUCCESS Test case {i} passed!")
        else:
            print(f"\nFAILED Test case {i} failed!")

        try:
            input("\nPress Enter to continue to next test...")
        except (EOFError, KeyboardInterrupt):
            break
