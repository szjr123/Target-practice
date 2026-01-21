import requests
import threading
import queue
from urllib.parse import urlparse
import urllib3
import time

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VulnScanner:
    def __init__(self, thread_num=300):
        self.thread_num = thread_num
        self.url_queue = queue.Queue()
        self.lock = threading.Lock()
        self.vuln_count = 0
        
        # 定义请求头
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept': '*/*',
            'Connection': 'Keep-Alive',
            'Accept-Charset': 'utf-8',
            'Accept-Encoding': 'gzip, deflate'
        }
    
    def load_urls(self, filename):
        """从文件加载URL列表"""
        try:
            with open(filename, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                print(f"[+] 已加载 {len(urls)} 个URL")
                for url in urls:
                    self.url_queue.put(url)
        except FileNotFoundError:
            print(f"[-] 文件 {filename} 不存在")
            exit(1)
        except Exception as e:
            print(f"[-] 读取文件时出错: {e}")
            exit(1)
    
    def check_vuln(self, url):
        """检测单个URL是否存在漏洞"""
        try:
            # 确保URL格式正确
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            target_url = f"{base_url}/api/user/all"
            
            # 设置Host头
            headers = self.headers.copy()
            headers['Host'] = parsed_url.netloc
            
            # 发送请求，禁用SSL验证，不跟随重定向
            response = requests.get(
                target_url,
                headers=headers,
                verify=False,
                allow_redirects=False,
                timeout=10
            )
            
            # 检查响应
            status_code = response.status_code
            
            # 3xx状态码认为不存在漏洞
            if 300 <= status_code < 400:
                print(f"[-] {url}: 状态码 {status_code} (3xx重定向)，漏洞不存在")
                return None
            
            # 状态码200且响应包含success
            if status_code == 200:
                # 检查响应内容中是否包含success（不区分大小写）
                if 'success' in response.text.lower():
                    print(f"[+] {url}: 漏洞存在! (状态码: {status_code})")
                    return url
                else:
                    print(f"[-] {url}: 状态码200但响应不包含success，漏洞不存在")
            else:
                print(f"[-] {url}: 状态码 {status_code}，漏洞不存在")
                
            return None
            
        except requests.exceptions.SSLError:
            print(f"[-] {url}: SSL错误，跳过")
            return None
        except requests.exceptions.ConnectionError:
            print(f"[-] {url}: 连接错误")
            return None
        except requests.exceptions.Timeout:
            print(f"[-] {url}: 请求超时")
            return None
        except Exception as e:
            print(f"[-] {url}: 检测时出错 - {str(e)}")
            return None
    
    def worker(self):
        """工作线程函数"""
        while True:
            try:
                url = self.url_queue.get_nowait()
            except queue.Empty:
                break
            
            vuln_url = self.check_vuln(url)
            
            # 如果发现漏洞，立即写入文件（只写入URL）
            if vuln_url:
                with self.lock:
                    self.write_vuln_url(vuln_url)
                    self.vuln_count += 1
            
            self.url_queue.task_done()
    
    def write_vuln_url(self, vuln_url):
        """将漏洞URL写入文件"""
        try:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(vuln_url + "\n")
            
            print(f"[!] 漏洞URL已写入 result.txt")
            
        except Exception as e:
            print(f"[-] 写入文件时出错: {e}")
    
    def start(self):
        """启动扫描"""
        print("[*] 开始漏洞扫描...")
        print(f"[*] 线程数: {self.thread_num}")
        print("[*] SSL验证已禁用")
        print("[*] 3xx状态码将视为漏洞不存在\n")
        
        # 清空或创建结果文件
        open('result.txt', 'w').close()
        
        # 创建并启动线程
        threads = []
        for i in range(self.thread_num):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 等待所有URL处理完成
        self.url_queue.join()
        
        # 等待所有线程完成
        for t in threads:
            t.join(timeout=1)
        
        # 输出统计信息
        print("\n" + "=" * 60)
        print(f"[*] 扫描完成!")
        print(f"[*] 发现漏洞数量: {self.vuln_count}")
        print(f"[*] 漏洞URL已保存到 result.txt")
        print("=" * 60)

def main():
    # 创建扫描器实例，设置线程数为300
    scanner = VulnScanner(thread_num=300)
    
    # 从url.txt加载URL
    scanner.load_urls('url.txt')
    
    # 开始扫描
    scanner.start()

if __name__ == "__main__":
    main()