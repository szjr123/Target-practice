import requests
import threading
from urllib.parse import urljoin
from queue import Queue
import time
import sys
import concurrent.futures
from threading import Lock

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

class VulnerabilityScanner:
    def __init__(self, thread_count=100):
        self.thread_count = thread_count
        self.results = []
        self.results_lock = Lock()  # 用于线程安全地添加结果
        self.processed_count = 0
        self.processed_lock = Lock()
        self.paths = [
            "/wp-content/uploads/fifu-plugin.log",
            "/wp-content/uploads/fifu-cloud.log"
        ]
        self.keywords = ['{"fifu-dimensions":', '"Invalid size:']
        
    def load_urls(self, filename):
        """从文件加载URL"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            return urls
        except FileNotFoundError:
            print(f"错误: 文件 {filename} 不存在")
            return []
        except Exception as e:
            print(f"读取文件时出错: {e}")
            return []
    
    def check_vulnerability(self, url):
        """检查单个URL的漏洞"""
        for path in self.paths:
            target_url = urljoin(url, path)
            
            try:
                # 发送GET请求，禁用SSL验证，不跟随重定向
                response = requests.get(
                    target_url,
                    verify=False,
                    allow_redirects=False,
                    timeout=10
                )
                
                # 更新进度
                with self.processed_lock:
                    self.processed_count += 1
                    if self.processed_count % 10 == 0:  # 每10个URL显示一次进度
                        print(f"已处理: {self.processed_count} 个URL")
                
                # 检查状态码
                if 300 <= response.status_code < 400:
                    # 3xx状态码认为不存在漏洞
                    continue
                
                elif response.status_code == 200:
                    # 检查响应体是否包含关键词
                    body = response.text
                    keyword1_found = self.keywords[0] in body
                    keyword2_found = self.keywords[1] in body
                    
                    if keyword1_found and keyword2_found:
                        # 漏洞存在
                        result = {
                            'url': target_url,
                            'status_code': response.status_code,
                            'keywords_found': [self.keywords[0], self.keywords[1]],
                            'response_length': len(body)
                        }
                        
                        # 立即写入结果文件
                        self.immediate_save_result(result)
                        print(f"[VULNERABLE] {target_url} - 漏洞存在!")
                        return True  # stop-at-first-match
                    
            except requests.exceptions.RequestException:
                # 静默处理请求错误，减少输出
                pass
            except Exception:
                # 静默处理其他错误
                pass
        
        return False
    
    def immediate_save_result(self, result):
        """立即将结果写入文件"""
        try:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(f"漏洞发现:\n")
                f.write(f"URL: {result['url']}\n")
                f.write(f"状态码: {result['status_code']}\n")
                f.write(f"发现的关键词: {', '.join(result['keywords_found'])}\n")
                f.write(f"响应长度: {result['response_length']} 字节\n")
                f.write("-" * 50 + "\n\n")
        except Exception as e:
            print(f"写入结果时出错: {e}")
    
    def scan_urls(self, urls):
        """使用线程池扫描URL"""
        print(f"开始扫描 {len(urls)} 个URL，使用 {self.thread_count} 个线程")
        
        # 清空或创建结果文件
        open('result.txt', 'w', encoding='utf-8').close()
        
        # 使用线程池执行
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            # 提交所有任务
            future_to_url = {executor.submit(self.check_vulnerability, url): url for url in urls}
            
            # 等待所有任务完成
            completed = 0
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f'{url} 生成异常: {exc}')
                completed += 1
        
        print(f"\n扫描完成! 共处理 {completed} 个URL")
        
        # 读取并显示最终结果数量
        try:
            with open('result.txt', 'r', encoding='utf-8') as f:
                content = f.read()
                vuln_count = content.count('漏洞发现:')
            print(f"共发现 {vuln_count} 个存在漏洞的URL")
        except:
            print("无法读取结果文件")
    
    def scan(self, url_file):
        """开始扫描"""
        print("开始加载URL...")
        urls = self.load_urls(url_file)
        
        if not urls:
            print("没有找到有效的URL，程序退出")
            return
        
        start_time = time.time()
        self.scan_urls(urls)
        end_time = time.time()
        
        print(f"总耗时: {end_time - start_time:.2f} 秒")

def main():
    scanner = VulnerabilityScanner(thread_count=100)
    
    # 检查文件是否存在
    try:
        with open('url.txt', 'r'):
            pass
    except FileNotFoundError:
        print("错误: url.txt 文件不存在")
        print("请创建 url.txt 文件并在每行输入一个URL")
        return
    
    scanner.scan('url.txt')

if __name__ == "__main__":
    main()