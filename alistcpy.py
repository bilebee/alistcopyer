import subprocess
import webbrowser  
import configparser  
import threading
from time import sleep
import requests
import os
import tkinter as tk
from tkinter import messagebox
import tkinter.ttk as ttk
import json
import hashlib  
import random  
import logging

# 配置日志系统
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('app.log', mode='a')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)
config = configparser.ConfigParser()
try:
    config.read('conf.ini', encoding='utf-8')
except configparser.Error:
    config = configparser.ConfigParser()
config['DEFAULT'].setdefault('url', 'http://localhost:5244')
config['DEFAULT'].setdefault('username', 'admin')
config['DEFAULT'].setdefault('password', '')
config['DEFAULT'].setdefault('autologin', 'False')
config['DEFAULT'].setdefault('save_password', 'False')
config['DEFAULT'].setdefault('filelog_level', 'info')
if not config.has_section('task'):
    config.add_section('task')
config['task'].setdefault('auto_sync_mode', 'False')
config['task'].setdefault('sync_direction', '0')
config['task'].setdefault('sync_tasktime', '0')
config['task'].setdefault('scan_interval', '0')
config['task'].setdefault('path1', '')
config['task'].setdefault('path2', '')
config['task'].setdefault('only_show_unsync', 'True')
config['task'].setdefault('force_refresh', 'False')
config['task'].setdefault('current_running_tasks_limit', '2')
# 新增配置项默认值
config['task'].setdefault('hide_source_missing', 'False')
TOTAL_SCANNED = 0
SYNC_FILES = 0
SYNC_DIRS = 0
UNSYNC_FOLDERS = 0
MISSING_SOURCE = 0
MISSING_TARGET = 0
SIZE_DIFF = 0
SCAN_IN_PROGRESS = False
EXITING = False
lock = threading.Lock()  
class DirectoryNode:
    def __init__(self, name, path, is_dir, syncok=False, unsynctype=0, size=0, in_progress=False, progress_stats='', progress_percent=0):
        path_fine = path.replace('/', '\\')
        hash_input = f"{path_fine}_{is_dir}"
        self.id = hashlib.md5(hash_input.encode('utf-8')).hexdigest()[:12]  
        logger.debug("获取节点: ID=%s, 哈希输入=%s", self.id, hash_input) 
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.syncok = syncok
        self.unsynctype = unsynctype
        self.size = size
        self.in_process = in_progress
        self.process_stats = progress_stats
        self.process_percent = progress_percent
        self.children = []
        self.parent = None
BASE_URL = config.get('DEFAULT', 'url', fallback='http://localhost:5244')  
USERNAME = config.get('DEFAULT', 'username', fallback='admin')
PASSWORD = config.get('DEFAULT', 'password', fallback='')
AUTOMATIC_LOGIN = config.getboolean('DEFAULT', 'autologin', fallback=False)  
def get_token(base_url, username, password):
    url = f"{base_url}/api/auth/login"
    payload = {
        'username': username,
        'password': password
    }
    logger.info("请求令牌，用户名: %s", username)
    try:
        response = requests.post(url, json=payload, timeout=10)  # 添加超时防止无限等待
        response.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        logger.error("无法连接到Alist服务器: %s", str(e))
        raise Exception("无法连接到服务器，请检查URL和网络连接。")
    except requests.exceptions.HTTPError as e:
        logger.error("HTTP错误: %s", str(e))
        raise Exception(f"HTTP错误: {response.status_code}, {response.text}")
    except Exception as e:
        logger.error("认证过程中发生错误: %s", str(e))
        raise
    token_data = response.json().get('data', {})
    logger.debug("令牌响应: %s", response)
    logger.debug("令牌数据: %s", token_data)
    if not token_data or 'token' not in token_data:
        logger.error("认证失败：响应中缺少有效的Token数据")
        raise Exception("认证失败：无效的响应数据")
    token = token_data['token']
    return token
def get_directory_contents(path, token, base_url):   #只有列出目录
    url = f"{base_url}/api/fs/dirs"
    headers = {
        'Authorization': f'{token}',  
        'Content-Type': 'application/json'
    }
    logger.debug("目录请求头: %s", headers)
    payload = json.dumps({
        "path": path,
        "password": "",
        "force_root": False
    })
    logger.debug("请求目录内容，路径: %s", path)  
    response = requests.post(url, headers=headers, data=payload)
    if response.status_code == 401:
        logger.warning("令牌过期，正在刷新...")
        token = get_token(base_url, USERNAME, PASSWORD)
        headers['Authorization'] = f'{token}'  
        response = requests.post(url, headers=headers, data=payload)  
    response.raise_for_status()
    json_response = response.json()
    logger.debug("目录响应数据: %s", json_response)  
    data = json_response.get('data')
    if data is None:
        return []  
    return data
def list_files_and_directories(path, token, base_url, refresh=False):    # 列出文件和目录
    url = f"{base_url}/api/fs/list"
    headers = {
        'Authorization': f'{token}',  
        'Content-Type': 'application/json'
    }
    payload = json.dumps({
        "path": path,
        "password": "",
        "page": 1,
        "per_page": 0,
        "refresh": refresh  
    })
    logger.debug("请求文件和目录列表，路径: %s", path)  
    response = requests.post(url, headers=headers, data=payload)
    if response.status_code == 401:
        logger.warning("令牌过期，正在刷新...") 
        token = get_token(base_url, USERNAME, PASSWORD)
        headers['Authorization'] = f'{token}'  
        response = requests.post(url, headers=headers, data=payload)  
    response.raise_for_status()
    json_response = response.json()
    data = json_response.get('data')
    if data is None:
        return []
    content = data.get('content', [])
    return content if isinstance(content, list) else []

def show_verification_info(node, path1, path2, token, base_url, root):  
    src_full = os.path.join(path1, node.path)
    dst_full = os.path.join(path2, node.path)
    if node.unsynctype == 1:
        try:
            src_info = get_obj_info(src_full, token, base_url)
        except Exception as e:
            messagebox.showerror("错误", f"获取源文件信息失败: {str(e)}")
            return
        dst_info = None
    elif node.unsynctype == 2:
        try:
            dst_info = get_obj_info(dst_full, token, base_url)
        except Exception as e:
            messagebox.showerror("错误", f"获取目标文件信息失败: {str(e)}")
            return
        src_info = None
    else:
        try:
            src_info = get_obj_info(src_full, token, base_url)
            dst_info = get_obj_info(dst_full, token, base_url)
        except Exception as e:
            messagebox.showerror("错误", f"获取校验信息失败: {str(e)}")
            return
    
    info_win = tk.Toplevel()
    info_win.title("文件校验信息")
    info_win.geometry("600x400")
    
    text = tk.Text(info_win, wrap=tk.WORD)
    text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    
    text.insert(tk.END, f"源路径: {src_full}\n")
    if src_info is not None:
        text.insert(tk.END, "\n源文件校验信息:\n")
        text.insert(tk.END, f"HashInfo: {src_info.get('hashinfo', 'N/A')}\n")
        text.insert(tk.END, f"Hash_Info: {src_info.get('hash_info', 'N/A')}\n")
    else:
        text.insert(tk.END, "\n源路径不存在或无法访问\n")
    
    text.insert(tk.END, f"\n目标路径: {dst_full}\n")
    if dst_info is not None:
        text.insert(tk.END, "\n目标文件校验信息:\n")
        text.insert(tk.END, f"HashInfo: {dst_info.get('hashinfo', 'N/A')}\n")
        text.insert(tk.END, f"Hash_Info: {dst_info.get('hash_info', 'N/A')}\n")
    else:
        text.insert(tk.END, "\n目标路径不存在或无法访问\n")
    
    scrollbar = tk.Scrollbar(info_win, command=text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text.config(yscrollcommand=scrollbar.set)
    
    info_win.transient(root)
    info_win.grab_set()

def get_obj_info(obj_fullpath, token, base_url):
    url = f"{base_url}/api/fs/get"
    payload = json.dumps({
        "path": obj_fullpath,
        "password": "",
        "page": 1,
        "per_page": 0,
        "refresh": True
    })
    headers = {
        'Authorization': f'{token}',
        'Content-Type': 'application/json'
    }
    logger.debug("请求对象信息，路径: %s", obj_fullpath)
    response = requests.request("POST", url, headers=headers, data=payload)
    json_response = response.json()
    data = json_response.get('data')
    return data
def copy_files(src_dir, dst_dir, names, token, base_url): 
    url = f"{base_url}/api/fs/copy"
    headers = {
        'Authorization': token,
        'Content-Type': 'application/json'
    }
    payload = json.dumps({
        "src_dir": src_dir,
        "dst_dir": dst_dir,
        "names": names
    })
    logger.info("复制文件: %s 到 %s", names, dst_dir)
    response = requests.post(url, headers=headers, data=payload)
    if response.status_code == 401:
        logger.warning("令牌过期，正在刷新...")
        token = get_token(base_url, USERNAME, PASSWORD)
        headers['Authorization'] = f'{token}'
        response = requests.post(url, headers=headers, data=payload)
    response.raise_for_status()
    logger.debug("复制响应: %s", response.json()) 
    return response.json()

def get_tasks_undone(token, base_url):
    url = f"{base_url}/api/admin/task/copy/undone"
    payload={}
    headers = {
        'Authorization': f'{token}'
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    json_response = response.json()
    if response.status_code == 401:
        logger.warning("令牌过期，正在刷新...")
        token = get_token(base_url, USERNAME, PASSWORD)
        headers['Authorization'] = f'{token}'
        response = requests.request("GET", url, headers=headers, data=payload)
    data = json_response.get('data')
    if data is None:
        return []
    return data

def get_tasks_done(token, base_url):
    url = f"{base_url}/api/admin/task/copy/done"
    payload={}
    headers = {
        'Authorization': f'{token}'
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    json_response = response.json()
    if response.status_code == 401:
        logger.warning("令牌过期，正在刷新...")
        token = get_token(base_url, USERNAME, PASSWORD)
        headers['Authorization'] = f'{token}'
        response = requests.request("GET", url, headers=headers, data=payload)
    data = json_response.get('data')
    return data
def clear_sucessful_tasks(token, base_url):
    url = f"{base_url}/api/admin/task/copy/clear_succeeded"
    payload={}
    headers = {
        'Authorization': f'{token}'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 401:
        logger.warning("令牌过期，正在刷新...")
        token = get_token(base_url, USERNAME, PASSWORD)
        headers['Authorization'] = f'{token}'
        response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 200:
        logger.info("清除了已完成任务")
        return True
    else:
        logger.warning("清除已完成任务失败")

def select_directory(token, base_url, current_path='', entry_var=None):  # 选择目录   这边改好了不要改动这里的东西
    def on_select():
        if tree.selection():
            selected_path.set(tree.selection()[0])
            if entry_var is not None:
                entry_var.set(selected_path.get())
        select_root.destroy()
    select_root = tk.Tk()
    select_root.title("目录选择")
    select_root.grab_set()
    selected_path = tk.StringVar(value=current_path)
    tree = ttk.Treeview(select_root, columns=('name',), show='tree')
    tree.heading('#0', text='Directory')
    tree.column('#0', width=400)
    scrollbar = ttk.Scrollbar(select_root, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.grid(row=0, column=1, sticky='ns')
    def populate_tree(path):
        tree.delete(*tree.get_children())
        contents = get_directory_contents(path, token, base_url)
        for item in contents:
            item_abs_path = os.path.join(path, item['name'])
            relative_path = os.path.relpath(item_abs_path, current_path)  
            tree.insert('', 'end', iid=relative_path, text=item['name'], open=False) 
    def on_open(event):
        if not tree.selection():
            return
        item = tree.selection()[0]
        item_abs_path = os.path.join(current_path, item) 
        if not tree.get_children(item):
            contents = get_directory_contents(item_abs_path, token, base_url)
            for sub_item in contents:
                sub_abs_path = os.path.join(item_abs_path, sub_item['name'])
                sub_relative_path = os.path.relpath(sub_abs_path, current_path)  
                tree.insert(item, 'end', iid=sub_relative_path, text=sub_item['name'], open=False)
        else:
            tree.item(item, open=not tree.item(item, "open"))
    tree.bind('<Double-1>', on_open)
    tree.grid(row=0, column=0, padx=5, pady=5)
    populate_tree(current_path)
    select_button = tk.Button(select_root, text="选择", command=on_select)
    select_button.grid(row=1, column=0, pady=10)
    select_root.mainloop()
    return selected_path.get()
def login_window():
    token = None  
    save_password = config.getboolean('DEFAULT', 'save_password', fallback=False)
    auto_login = config.getboolean('DEFAULT', 'autologin', fallback=False)
    def on_login():
        nonlocal token
        base_url = base_url_entry.get()
        username = username_entry.get()  
        password = password_entry.get()
        try:
            config.read('conf.ini', encoding='utf-8')
            token = get_token(base_url, username, password)
            if save_password_var.get():
                config['DEFAULT']['password'] = password
            else:
                config['DEFAULT']['password'] = ''
            config['DEFAULT']['autologin'] = str(auto_login_var.get())
            config['DEFAULT']['username'] = username  
            config['DEFAULT']['save_password'] = str(save_password_var.get())
        except Exception as e:
            config['DEFAULT']['password'] = ''
            config['DEFAULT']['autologin'] = 'False'
            messagebox.showerror("登录失败", f"错误: {str(e)}")  
        finally:
            with open('conf.ini', 'w', encoding='utf-8') as configfile:
                config.write(configfile)
        if token:
            login_root.destroy() 
            main_window(token, base_url)
    login_root = tk.Tk()
    login_root.title("连接至alist")
    login_root.bind("<Return>", lambda event: on_login())  
    form_frame = tk.Frame(login_root)
    form_frame.grid(row=0, column=0, columnspan=2, padx=5, pady=5)
    tk.Label(form_frame, text="alist URL:").grid(row=0, column=0, sticky='w')
    base_url_entry = tk.Entry(form_frame, width=50)
    base_url_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
    base_url_entry.insert(0, BASE_URL)  
    tk.Label(form_frame, text="用户名:").grid(row=1, column=0, sticky='w')
    username_entry = tk.Entry(form_frame, width=50)
    username_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
    username_entry.insert(0, USERNAME)  
    tk.Label(form_frame, text="密码:").grid(row=2, column=0, sticky='w')
    password_entry = tk.Entry(form_frame, width=50, show="*")
    password_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
    if save_password:  
        password_entry.insert(0, PASSWORD)
    save_password_var = tk.IntVar(value=save_password)
    auto_login_var = tk.IntVar(value=auto_login)
    tk.Checkbutton(form_frame, text="保存密码", variable=save_password_var).grid(row=3, column=0, sticky='w')
    tk.Checkbutton(form_frame, text="下次自动登录", variable=auto_login_var).grid(row=3, column=1, sticky='w')
    login_button = tk.Button(login_root, text="登录", command=on_login)
    login_button.grid(row=4, column=0, columnspan=2, pady=10)
    if AUTOMATIC_LOGIN:
        auto_login_var.set(AUTOMATIC_LOGIN)
        save_password_var.set(save_password)
        login_root.after(100, on_login)
        login_root.mainloop()
    else:
        login_root.mainloop()
def main_window(token, base_url):
    root = tk.Tk()
    root.title("Alist增量同步实用程序")
    root.geometry("1280x800")

    global TOTAL_SCANNED, SYNC_FILES, SYNC_DIRS, UNSYNC_FOLDERS, \
           MISSING_SOURCE, MISSING_TARGET, SIZE_DIFF, SCAN_IN_PROGRESS, lock
    global nodes, ops_queue  
    nodes = {} 
    ops_queue = []  
    exit_flag = threading.Event()  
    monitor_thread = None  
    interval_var = tk.DoubleVar(value=float(config.get('task', 'scan_interval', fallback='0')))

    def update_table():
        global EXITING
        if EXITING:
            return
        diff_table.delete(*diff_table.get_children())
        unsynctype_mapping = {
            0: "已同步",
            1: "目标缺失",
            2: "源缺失",
            3: "原中的文件更大",
            4: "目标中的文件更大",
            5: "同步运行中"
        }
        for node in nodes.values():
            if show_unsync_var.get() and node.syncok:
                continue
            # 新增过滤条件
            if hide_source_missing_var.get() and node.unsynctype == 2:
                continue
            is_dir_text = "文件夹" if node.is_dir else "文件"
            unsync_reason = unsynctype_mapping.get(node.unsynctype, "未知")
            if (node.syncok and node.unsynctype !=0) or (not node.syncok and node.unsynctype ==0):
                combined_status = f"出现未知情况：{node.unsynctype},{node.syncok}"
            else:
                if node.syncok:
                    combined_status = "已同步"
                else:
                    combined_status = unsync_reason  
            progress_percent = ""
            progress_info = ""
            if node.in_process:
                progress_percent = f"{node.process_percent:.1f}%" if node.process_percent is not None else ""
                progress_info = node.process_stats if node.process_stats else ""
            diff_table.insert("", "end", iid=str(node.id), values=( 
                node.name, node.path, is_dir_text, 
                combined_status, node.size,  
                progress_percent, progress_info
            ))
        with lock:
            sync_files_var.set(str(SYNC_FILES))
            sync_dirs_var.set(str(SYNC_DIRS))
            unsync_folders_var.set(str(UNSYNC_FOLDERS))
            missing_source_var.set(str(MISSING_SOURCE))
            missing_target_var.set(str(MISSING_TARGET))
            size_diff_var.set(str(SIZE_DIFF))
    def check_and_start_scan():
        path1 = path1_var.get().strip()
        path2 = path2_var.get().strip()
        if not path1 or not path2:
            messagebox.showwarning("路径缺失", "原路径和目标路径不能为空")
            return
        threading.Thread(target=start_background_scan).start()
    def on_close():
        global EXITING
        EXITING = True
        exit_flag.set()  
        if monitor_thread:
            monitor_thread.join()  
        root.destroy()  
        path1_var.set("")
        path2_var.set("")
    root.protocol("WM_DELETE_WINDOW", on_close)
    def conf_task():
        conf_window = tk.Toplevel(root)
        conf_window.title("配置任务")
        auto_sync_var = tk.IntVar(value=config.getboolean('task', 'auto_sync_mode', fallback=False))
        task_time_var = tk.StringVar(value=config.get('task', 'sync_tasktime', fallback='0'))
        auto_sync_checkbox = tk.Checkbutton(conf_window, text="启用自动同步,开启并保存后启动软件会自动扫描差异", variable=auto_sync_var)
        auto_sync_checkbox.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        tk.Label(conf_window, text="自动任务延时启动时间（分钟）:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        task_time_entry = tk.Entry(conf_window, textvariable=task_time_var, width=10)
        task_time_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Label(conf_window, text="注意：如果使用任务计划程序请注意，必须设置起始路径\n在错误的路径下会导致无法读配置文件而出错。\n会使用当前的路径和设置。").grid(row=4, column=0, columnspan=2, pady=10)
        def open_task_scheduler():
            # 打开Windows任务计划程序 taskschd.msc
            try:
                subprocess.Popen(['taskschd.msc'], shell=True)
            except Exception as e:
                messagebox.showerror("错误", f"无法打开任务计划程序：{e}")

        tk.Button(conf_window, text="打开Windows任务计划程序", command=open_task_scheduler).grid(row=2, column=0, columnspan=2, pady=20)
        def save_config():
            config.set('task', 'auto_sync_mode', str(auto_sync_var.get()))
            config.set('task', 'sync_tasktime', task_time_var.get())
            config.set('task', 'sync_direction', sync_direction_var.get())
            config.set('task', 'path1', path1_var.get())
            config.set('task', 'path2', path2_var.get())
            config.set('task', 'only_show_unsync', str(show_unsync_var.get()))
            config.set('task', 'force_refresh', str(use_refresh_var.get()))
            # 新增：保存扫描间隔时间配置
            config.set('task', 'scan_interval', str(interval_var.get()))
            with open('conf.ini', 'w', encoding='utf-8') as configfile:
                config.write(configfile)
            conf_window.destroy()
        save_btn = tk.Button(conf_window, text="保存任务设置", command=save_config)
        save_btn.grid(row=2, column=1, columnspan=2, pady=10)

    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)
    main_frame = tk.Frame(root)
    main_frame.grid(row=0, column=0, padx=5, pady=5, sticky='nsew')
    tk.Label(main_frame, text="原路径:").grid(row=0, column=0, padx=5, pady=5)
    path1_var = tk.StringVar(value=config.get('task', 'path1', fallback=''))
    path1_entry = tk.Entry(main_frame, width=50, textvariable=path1_var)
    path1_entry.grid(row=0, column=1, padx=5, pady=5)
    browse_button1 = tk.Button(main_frame, text="浏览", command=lambda: select_directory(token, base_url, "", path1_var))
    browse_button1.grid(row=0, column=2, padx=5, pady=5)
    clear_button1 = tk.Button(main_frame, text="清除", command=lambda: path1_var.set(""))
    clear_button1.grid(row=0, column=3, padx=5, pady=5)
    interval_var = tk.DoubleVar(value=float(config.get('task', 'scan_interval', fallback='0')))
    tk.Label(main_frame, text="遍历时间间隔(s):").grid(row=0, column=5, pady=5)
    scale = ttk.Scale(
        main_frame, 
        from_=0, 
        to=10, 
        variable=interval_var,
        command=lambda x: interval_var.set(round(float(x),1)) 
    )
    scale.grid(row=0, column=6, pady=5)
    value_label = tk.Label(main_frame, textvariable=interval_var)
    value_label.grid(row=0, column=7, pady=5)
    use_refresh_var = tk.IntVar(value=0)
    tk.Label(main_frame, text="最大遍历深度:").grid(row=0, column=8, padx=5, pady=5)
    max_depth_var = tk.IntVar(value=16)
    max_depth_entry = tk.Entry(main_frame, width=5, textvariable=max_depth_var)
    max_depth_entry.grid(row=0, column=9, padx=5, pady=5)
    tk.Label(main_frame, text="目标路径:").grid(row=1, column=0, padx=5, pady=5)
    path2_var = tk.StringVar(value=config.get('task', 'path2', fallback=''))
    path2_entry = tk.Entry(main_frame, width=50, textvariable=path2_var)
    path2_entry.grid(row=1, column=1, padx=5, pady=5)
    browse_button2 = tk.Button(main_frame, text="浏览", command=lambda: select_directory(token, base_url, "", path2_var))
    browse_button2.grid(row=1, column=2, padx=5, pady=5)
    clear_button2 = tk.Button(main_frame, text="清除", command=lambda: path2_var.set(""))
    clear_button2.grid(row=1, column=3, padx=5, pady=5)
    init_compare_button = tk.Button(main_frame, text="开始比对", command=check_and_start_scan)
    init_compare_button.grid(row=0, column=4, pady=5)
    conf_task_button = tk.Button(main_frame, text="自动任务", command=conf_task)
    conf_task_button.grid(row=1, column=4, pady=5)
    direction_map = {
        '0': "不自动同步",
        '1': "原到目标",
        '2': "强制原到目标(未实现)",
        '3': "双向"
    }
    sync_direction_var = tk.StringVar()
    current_running_tasks_limit_var = tk.IntVar(value=config.getint('task', 'current_running_tasks_limit', fallback=2))
    initial_key = config.get('task', 'sync_direction', fallback='0')
    selected_text = direction_map.get(initial_key, "不自动同步")
    sync_direction_var.set(initial_key)  
    sync_direction_combobox = ttk.Combobox(
        main_frame,
        values=list(direction_map.values()),  
        state="readonly"
    )
    sync_direction_combobox.set(selected_text)  
    def on_sync_direction_change(event):
        selected_text = sync_direction_combobox.get()
        for key, value in direction_map.items():
            if value == selected_text:
                sync_direction_var.set(key)
                break
    sync_direction_combobox.bind("<<ComboboxSelected>>", on_sync_direction_change)
    tk.Label(main_frame, text="自动同步方向:").grid(row=0, column=10, padx=5, pady=5)
    sync_direction_combobox.grid(row=0, column=11, padx=5, pady=5)
    show_unsync_var = tk.IntVar(value=config.getboolean('task', 'only_show_unsync', fallback=True))
    hide_source_missing_var = tk.IntVar(value=config.getboolean('task', 'hide_source_missing', fallback=False))
    filter_checkbox = tk.Checkbutton(main_frame, text="仅显示未同步", variable=show_unsync_var, command=update_table)
    filter_checkbox.grid(row=1, column=5, pady=5)  
    hide_source_missing_checkbox = tk.Checkbutton(main_frame, text="不显示原缺失", variable=hide_source_missing_var, command=update_table)
    hide_source_missing_checkbox.grid(row=1, column=8, pady=5)  
    refresh_checkbox = tk.Checkbutton(main_frame, text="使用强制刷新", variable=use_refresh_var)
    refresh_checkbox.grid(row=1, column=6, pady=5)
    diff_frame = tk.Frame(root)
    diff_frame.grid(row=1, column=0, sticky='nsew')
    diff_table = ttk.Treeview(diff_frame, 
        columns=('name', 'path', 'is_dir', 'status', 'size', 'progress_percent', 'progress_info'),  
        show='headings'
    )
    diff_table.heading('name', text='名称')
    diff_table.heading('path', text='路径')
    diff_table.heading('is_dir', text='类型')
    diff_table.heading('status', text='同步状态')  
    diff_table.heading('size', text='大小')
    diff_table.heading('progress_percent', text='进度')  
    diff_table.heading('progress_info', text='状态信息')  
    diff_table.column('progress_percent', width=100, stretch=True, minwidth=80)  
    diff_table.column('progress_info', width=200, stretch=True, minwidth=150)  
    diff_table.column('name', width=150, stretch=True)
    diff_table.column('path', width=300, stretch=True, minwidth=200)
    diff_table.column('is_dir', width=80, stretch=False)
    diff_table.column('status', width=200, stretch=True)
    diff_table.column('size', width=100, stretch=False)
    scrollbar_diff = ttk.Scrollbar(diff_frame, orient="vertical", command=diff_table.yview)
    diff_table.configure(yscrollcommand=scrollbar_diff.set)
    scrollbar_diff.pack(side='right', fill='y')
    diff_table.pack(side='left', fill='both', expand=True)
    diff_table.bind("<Double-1>", lambda event: on_row_double_click(diff_table, path1_var, path2_var, token, base_url))
    def show_context_menu(event):
        path1 = path1_var.get()
        path2 = path2_var.get()
        selected_item = diff_table.selection()
        if not selected_item:
            return
        item_id = selected_item[0]
        item = diff_table.item(item_id)
        node = nodes.get(item_id)
        if not node:
            return
        path = node.path
        parent_path = os.path.dirname(path)
        menu = tk.Menu(root, tearoff=0)
        menu.add_command(label="刷新所在目录状态", command=lambda p=parent_path: refresh_path(p))
        if node.unsynctype == 1:
            menu.add_command(label="直接复制", command=lambda p=path: direct_copy_item(p))
        if not node.is_dir and node.unsynctype in (0,1,2,3,4):
            menu.add_command(
                label="查看校验信息",
                command=lambda node=node, p1=path1, p2=path2:  
                    show_verification_info(node, p1, p2, token, BASE_URL, root)  
            )
        show_source = True
        show_target = True
        if node.unsynctype == 1:
            show_target = False
        elif node.unsynctype == 2:
            show_source = False
        if show_source:
            menu.add_command(
                label="在Alist中打开原路径",
                command=lambda p=node.path: webbrowser.open(f"{BASE_URL}/{path1}/{p}")
            )
        if show_target:
            menu.add_command(
                label="在Alist中打开目标路径",
                command=lambda p=node.path: webbrowser.open(f"{BASE_URL}/{path2}/{p}")
            )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
    def refresh_path(parent_path):
        path1 = path1_var.get()
        path2 = path2_var.get()
        def refresh_worker():
            global nodes
            try:
                new_nodes = build_tree(
                    path1_base=path1,
                    path2_base=path2,
                    current_rel_path=parent_path,
                    interval=0,
                    use_refresh=True,
                    max_depth=0
                )
                nodes.update(new_nodes)
            finally:
                root.after(0, update_table)
        threading.Thread(target=refresh_worker).start()
    def direct_copy_item(selected_path):
        path1 = path1_var.get()
        path2 = path2_var.get()
        filename = os.path.basename(selected_path)
        src_dir = os.path.dirname(os.path.join(path1, selected_path))
        dst_dir = os.path.dirname(os.path.join(path2, selected_path))
        def copy_worker():
            try:
                copy_files(src_dir, dst_dir, [filename], token, BASE_URL)
            except Exception as e:
                root.after(0, lambda: messagebox.showerror("复制失败", str(e)))
        threading.Thread(target=copy_worker).start()
    diff_table.bind("<Button-3>", show_context_menu)
    def on_row_double_click(table, path1_var, path2_var, token, base_url):
        selected_item = table.selection()
        logger.debug("双击选中项:%s", selected_item)  
        if not selected_item:
            logger.debug("未选中任何行")  
            return
        item_id = selected_item[0]
        logger.debug("选中IID: %s",item_id)  
        item = table.item(item_id)
        node = nodes.get(item_id)
        logger.debug("节点存在性检查: %s 在 nodes 中吗? ",node)  
        if not node:
            logger.debug("未找到对应节点，IID: %s",item_id)  
            return
        path = node.path
        logger.debug("节点路径: %s",path)  
        unsynctype = node.unsynctype
        logger.debug("节点类型: %s",unsynctype)
        is_dir = node.is_dir
        show_operation_window(path, unsynctype, is_dir, path1_var.get(), path2_var.get(), token, base_url)
    def show_operation_window(node_path, unsynctype, is_dir, path1, path2, token, base_url):
        def show_success_message(message):
            success_win = tk.Toplevel()
            success_win.title("操作成功")
            success_win.geometry("400x150")
            tk.Label(success_win, text=message).pack(pady=20)
            success_win.after(5000, success_win.destroy)
        op_win = tk.Toplevel()
        op_win.title("比对信息")
        op_win.geometry("800x450")
        src_full = os.path.join(path1, node_path)
        dst_full = os.path.join(path2, node_path)
        ftype = "文件夹" if is_dir else "文件"
        filename = os.path.basename(node_path)
        title_label = tk.Label(op_win, text=f"{ftype}名称：{filename}", font=('Arial', 12, 'bold'))
        title_label.pack(padx=10, pady=10, anchor='w')
        if unsynctype == 1:
            dst_info = None
        else:
            dst_info = get_obj_info(dst_full, token, base_url)
        if unsynctype == 2:
            src_info = None
        else:
            src_info = get_obj_info(src_full, token, base_url)
        src_hash = src_info.get('hashinfo') if src_info else None
        src_size = src_info.get('size') if src_info else None
        src_modified = src_info.get('modified') if src_info else None
        src_provider = src_info.get('provider') if src_info else None
        dst_hash = dst_info.get('hashinfo') if dst_info else None
        dst_size = dst_info.get('size') if dst_info else None
        dst_modified = dst_info.get('modified') if dst_info else None
        dst_provider = dst_info.get('provider') if dst_info else None
        op_table = ttk.Treeview(op_win, columns=('info','src', 'dst'), show='headings')
        op_table.column('info', width=100, stretch=False, minwidth=80)
        op_table.column('src', width=300, stretch=True, minwidth=200)
        op_table.column('dst', width=300, stretch=True, minwidth=200)
        op_table.heading('src', text='原')
        op_table.heading('dst', text='目标')
        op_table.insert('', 'end', values=('路径',src_full, dst_full))
        op_table.insert('', 'end', values=('校验',src_hash, dst_hash))
        op_table.insert('', 'end', values=('大小',src_size, dst_size))
        op_table.insert('', 'end', values=('修改时间',src_modified, dst_modified))
        op_table.insert('', 'end', values=('提供者',src_provider, dst_provider))
        op_table.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        
        def copy_source_to_target():
                copy_files(os.path.dirname(src_full), os.path.dirname(dst_full), 
                          [os.path.basename(node_path)], token, base_url)
                op_win.destroy()
                show_success_message("已复制源文件到目标路径")
            
        def copy_target_to_source():
                copy_files(os.path.dirname(dst_full), os.path.dirname(src_full), 
                          [os.path.basename(node_path)], token, base_url)
                op_win.destroy()
                show_success_message("已复制目标文件到源路径")
        if unsynctype in [3,4]:
            button_frame = tk.Frame(op_win)
            button_frame.pack(pady=20)
            tk.Button(op_win, text="在Alist中打开目标路径", 
                     command=lambda: webbrowser.open(f"{base_url}/{dst_full.replace(' ', '%20')}")).pack(pady=5)
        
            tk.Button(op_win, text="在Alist中打开原路径", 
                     command=lambda: webbrowser.open(f"{base_url}/{src_full.replace(' ', '%20')}")).pack(pady=5)
            tk.Button(button_frame, text="复制源到目标", command=copy_source_to_target).pack(side=tk.LEFT, padx=10)
            tk.Button(button_frame, text="复制目标到源", command=copy_target_to_source).pack(side=tk.RIGHT, padx=10)
        else:
            if unsynctype in [1, 2]:
                tk.Label(op_win, text=f"将 {filename} 从源路径复制到目标路径？").pack(padx=10, pady=5)
                button_frame = tk.Frame(op_win)
                button_frame.pack(pady=10)
                if unsynctype == 1:
                    btn_text = "复制源到目标"
                    btn_command = copy_source_to_target
                    tk.Button(op_win, text="在Alist中打开原路径", 
                     command=lambda: webbrowser.open(f"{base_url}/{src_full.replace(' ', '%20')}")).pack(pady=5)
                else:
                    btn_text = "复制目标到源"
                    btn_command = copy_target_to_source
                    tk.Button(op_win, text="在Alist中打开目标路径", 
                     command=lambda: webbrowser.open(f"{base_url}/{dst_full.replace(' ', '%20')}")).pack(pady=5)
                tk.Button(button_frame, text=btn_text, command=btn_command,
                         padx=20, pady=10, width=15).pack(side=tk.LEFT, padx=5)
            else:
                if unsynctype ==5: tk.Button(op_win, text="打开任务管理页面", command=lambda: webbrowser.open(f"{base_url}/@manage/tasks/copy")).pack(pady=10)
                if unsynctype == 0:
                    tk.Button(op_win, text="在Alist中打开目标路径", 
                                command=lambda: webbrowser.open(f"{base_url}/{dst_full.replace(' ', '%20')}")).pack(pady=5)
                
                    tk.Button(op_win, text="在Alist中打开原路径", 
                                command=lambda: webbrowser.open(f"{base_url}/{src_full.replace(' ', '%20')}")).pack(pady=5)
                    return
                else:
                    tk.Label(op_win, text="当前状态不支持操作").pack(padx=10, pady=10)
        op_win.transient(root)
    def parse_task_paths(name_str):
        parts = name_str.split(") to [/")
        if len(parts) != 2:
            raise ValueError(f"任务名称格式错误: {name_str}")
        source_part = parts[0].split("copy [/")[-1]
        destination_part = parts[1][:-1] if parts[1].endswith(')') else parts[1]
        source_path = source_part.replace("](/", "/")
        destination_path = destination_part.replace("](/", "/")
        return source_path, destination_path
    def monitor_tasks(initial_path1_o, initial_path2_o, token, base_url, root, exit_flag):
        global EXITING
        def update_nodes(update_fullpath, abspath_input, percent, error, inprocess, state, initial_path1, initial_path2):
            if abspath_input and abspath_input.startswith('/'):
                abspath = abspath_input[1:]
            else:
                abspath = abspath_input
            if abspath_input and abspath_input.startswith('\\'):
                abspath = abspath_input[1:]
            else:
                abspath = abspath_input
            is_processed = False
            obj_info = get_obj_info(update_fullpath, token, base_url)
            if obj_info is not None:
                is_dir = obj_info.get('is_dir')
                name = obj_info.get('name', '')  
                hash_input = f"{abspath}_{is_dir}"  
                logger.debug("哈希输入: %s",hash_input)
                node_id = hashlib.md5(hash_input.encode('utf-8')).hexdigest()[:12]  
                logger.debug("节点ID: %s",node_id)
                current_rel_path = os.path.relpath(update_fullpath, initial_path1)  
                if node_id not in nodes:  
                    new_nodes = build_tree(
                        initial_path1, initial_path2,  
                        abspath, 
                        interval=0.0,
                        use_refresh=True,
                        max_depth=0  
                    )
                    nodes.update(new_nodes)
                    is_processed = True
                else:
                    node = nodes[node_id]
                    if inprocess == False:
                        if state == 2:
                            logger.debug("节点 %s 已完成同步",node_id)
                            new_nodes = build_tree(
                                initial_path1, initial_path2, 
                                abspath, 
                                interval=0.0,
                                use_refresh=True,
                                max_depth=0  
                            )
                            nodes.update(new_nodes)
                            src_full = os.path.join(initial_path1, current_rel_path)
                            dst_full = os.path.join(initial_path2, current_rel_path)
                            if src_full and dst_full:
                                src_data = get_obj_info(src_full, token, base_url)
                                dst_data = get_obj_info(dst_full, token, base_url) 
                                logger.debug("数据：%s，%s",src_data,dst_data)
                                if src_data and dst_data:
                                    if src_data.get('is_dir') == dst_data.get('is_dir'):
                                        if src_data.get(is_dir) ==True: 
                                            node.syncok = True
                                            logger.debug("同步成功")
                                            node.unsynctype = 0
                                            is_processed = True
                                        else:
                                            if src_data.get('size') == dst_data.get('size'):
                                                node.syncok = True
                                                logger.debug("同步成功")
                                                node.unsynctype = 0
                                                is_processed = True
                    if state == 1:
                        logger.debug("节点 %s 正在处理中",node_id)
                        node.unsynctype = 5
                    logger.debug("节点 %s 同步状态：%s",node_id,state)
                    node.is_dir = is_dir
                    node.size = obj_info.get('size', 0)  
                    node.in_process = inprocess  
                    node.process_percent = percent  
                    node.process_stats = error  
            return(is_processed)
        need_clear = False
        while not exit_flag.is_set(): 
            current_path1_o = path1_var.get()
            current_path2_o = path2_var.get()
            current_path1 = os.path.normpath(current_path1_o)
            current_path2 = os.path.normpath(current_path2_o)
            initial_path1 = os.path.normpath(initial_path1_o)
            initial_path2 = os.path.normpath(initial_path2_o)
            if current_path1 != initial_path1 or current_path2 != initial_path2:
                logger.info("路径已更改，取消监控")
                return
            unsync_nodes = [node for node in nodes.values() if node.unsynctype in (1, 2, 5)]
            if unsync_nodes:
                selected_node = random.choice(unsync_nodes)
                parent_path = os.path.dirname(selected_node.path)
                new_nodes = build_tree(
                    initial_path1_o,
                    initial_path2_o,
                    parent_path,
                    interval=0,
                    use_refresh=True,
                    max_depth=0
                )
                nodes.update(new_nodes)
            undone_tasks = get_tasks_undone(token, base_url)
            done_tasks = get_tasks_done(token, base_url)
            current_running_tasks = 0
            for task in undone_tasks:
                if task['state'] == 1:
                    current_running_tasks += 1
            for task in undone_tasks + done_tasks:
                logger.debug(f"任务: {task}")
                state = task['state']
                name_str = task['name']
                percent = task['progress']
                error = task['error']
                need_clear = False
                try:
                    src_path_o, dst_path_o = parse_task_paths(name_str)
                    src_path = os.path.normpath(src_path_o)
                    dst_path = os.path.normpath(dst_path_o)
                except ValueError as e:
                    logger.error("解析任务名失败: %s",e)
                    continue
                logger.debug("正在解析任务: %s", task)
                logger.debug("源路径：%s", src_path)
                logger.debug("目标路径：%s", dst_path)
                parse = False
                if src_path.startswith(initial_path1) and dst_path.startswith(initial_path2):
                    logger.debug("路径头检查通过")
                    src_abspath = src_path[len(initial_path1):]
                    dst_abspath = dst_path[len(initial_path2):]
                    parse = True
                elif src_path.startswith(initial_path2) and dst_path.startswith(initial_path1):
                    logger.debug("路径头检查通过")
                    src_abspath = src_path[len(initial_path2):]
                    dst_abspath = dst_path[len(initial_path1):]
                    parse = True
                if parse:
                    logger.debug("源路径：%s", src_abspath)
                    logger.debug("目标路径：%s", dst_abspath)
                    if len(dst_abspath) == 0:
                        logger.debug("目标路径为空")
                        if src_abspath[len(dst_abspath)] == '\\':
                            if state == 1:
                                inprocess = True
                            else:
                                inprocess = False
                            frag = update_nodes(src_path,src_abspath,percent,error,inprocess,state, initial_path1, initial_path2)
                            if frag == True:
                                need_clear = True
                            else:
                                need_clear = False
                    else:
                        if src_abspath[:len(dst_abspath)] == dst_abspath:
                            if src_abspath[len(dst_abspath)] == '\\':
                                if state == 1:
                                    inprocess = True
                                else:
                                    inprocess = False
                                frag = update_nodes(src_path,src_abspath,percent,error,inprocess,state, initial_path1, initial_path2)
                                if frag == True:
                                    need_clear = True
                                else:
                                    need_clear = False
            if need_clear == True:
                clear_sucessful_tasks(token, base_url)
                need_clear = False
            if not exit_flag.is_set():
                root.after(0, update_table)
            sleep(10)
            current_running_tasks_limit = current_running_tasks_limit_var.get()
            sync_direction = sync_direction_var.get()
            if sync_direction in ['1', '3']:
                unsync_nodes = [node for node in nodes.values() if node.unsynctype == 1]
                if unsync_nodes and current_running_tasks < current_running_tasks_limit:
                    selected_node = random.choice(unsync_nodes)
                    filename = selected_node.name
                    src_dir = os.path.dirname(os.path.join(initial_path1_o, selected_node.path))
                    dst_dir = os.path.dirname(os.path.join(initial_path2_o, selected_node.path))
                    copy_files(src_dir, dst_dir, [filename], token, base_url)
                    logger.debug("随机自动同步文件：%s",filename)
            if sync_direction == '3':
                unsync_nodes2 = [node for node in nodes.values() if node.unsynctype == 2]
                if unsync_nodes2 and current_running_tasks < current_running_tasks_limit:
                    selected_node2 = random.choice(unsync_nodes2)
                    filename = selected_node2.name
                    src_dir = os.path.dirname(os.path.join(initial_path2_o, selected_node2.path))
                    dst_dir = os.path.dirname(os.path.join(initial_path1_o, selected_node2.path))
                    copy_files(src_dir, dst_dir, [filename], token, base_url)
                    logger(f"随机反向同步文件：%s",filename)
            if all(node.unsynctype == 0 for node in nodes.values()):
                if config.getboolean('task', 'auto_sync_mode'):  
                    exit_flag.set()
                    logger.info("所有文件已同步，程序退出。")
                    root.after(0, root.destroy)  
                return
            if exit_flag.is_set():
                return
    def start_background_scan():
        global SCAN_IN_PROGRESS, lock, TOTAL_SCANNED, SYNC_FILES, SYNC_DIRS, UNSYNC_FOLDERS, MISSING_SOURCE, MISSING_TARGET, SIZE_DIFF, nodes
        with lock:
            SCAN_IN_PROGRESS = True
            scan_status.set("扫描中...")
            TOTAL_SCANNED = 0
            SYNC_FILES = 0
            SYNC_DIRS = 0
            UNSYNC_FOLDERS = 0
            MISSING_SOURCE = 0
            MISSING_TARGET = 0
            SIZE_DIFF = 0
            nodes.clear()  
        root.after(0, lambda: init_compare_button.config(state=tk.DISABLED))
        root.after(0, lambda: path1_entry.config(state=tk.DISABLED))
        root.after(0, lambda: path2_entry.config(state=tk.DISABLED))
        root.after(0, lambda: browse_button1.config(state=tk.DISABLED))
        root.after(0, lambda: browse_button2.config(state=tk.DISABLED))
        root.after(0, lambda: clear_button1.config(state=tk.DISABLED))
        root.after(0, lambda: clear_button2.config(state=tk.DISABLED))
        def scan_worker():
            global nodes
            try:
                nodes = build_tree(
                    path1_var.get(), 
                    path2_var.get(), 
                    "", 
                    interval=interval_var.get(), 
                    use_refresh=bool(use_refresh_var.get()), 
                    max_depth=max_depth_var.get()  
                )
            finally:
                with lock:
                    SCAN_IN_PROGRESS = False
                    scan_status.set("扫描完成")
                root.after(0, lambda: path1_entry.config(state=tk.NORMAL))
                root.after(0, lambda: path2_entry.config(state=tk.NORMAL))
                root.after(0, lambda: browse_button1.config(state=tk.NORMAL))
                root.after(0, lambda: browse_button2.config(state=tk.NORMAL))
                root.after(0, lambda: clear_button1.config(state=tk.NORMAL))
                root.after(0, lambda: clear_button2.config(state=tk.NORMAL))
                root.after(0, update_table)
                root.after(0, lambda: init_compare_button.config(state=tk.NORMAL))
                initial_path1 = os.path.normpath(path1_var.get())
                initial_path2 = os.path.normpath(path2_var.get())
                threading.Thread(target=monitor_tasks, args=(
                    initial_path1, initial_path2, token, base_url, root, exit_flag
                )).start()
        threading.Thread(target=scan_worker).start()
        root.after(0, refresh_ui)  
    def refresh_ui():
        with lock:
            current_scanned = TOTAL_SCANNED
            sync_files = SYNC_FILES
            sync_dirs = SYNC_DIRS
            unsync_folders = UNSYNC_FOLDERS
            missing_source = MISSING_SOURCE
            missing_target = MISSING_TARGET
            size_diff = SIZE_DIFF
            is_scanning = SCAN_IN_PROGRESS
        scanned_count.set(str(current_scanned))
        sync_files_var.set(str(sync_files))
        sync_dirs_var.set(str(sync_dirs))
        unsync_folders_var.set(str(unsync_folders))
        missing_source_var.set(str(missing_source))
        missing_target_var.set(str(missing_target))
        size_diff_var.set(str(size_diff))
        if is_scanning:
            root.after(100, refresh_ui) 
        else:
            pass
    def build_tree(path1_base, path2_base, current_rel_path, interval=0.1, use_refresh=False, max_depth=16):
        if exit_flag.is_set():  
            return {}
        logger.debug("正在构建树: 当前路径 %s，最大深度 %s", current_rel_path, max_depth)  
        nodes = {}
        if max_depth < 0:
            return {}
        global TOTAL_SCANNED, SYNC_FILES, SYNC_DIRS, UNSYNC_FOLDERS, \
               MISSING_SOURCE, MISSING_TARGET, SIZE_DIFF, lock
        current_full_path1 = os.path.join(path1_base, current_rel_path)
        current_full_path2 = os.path.join(path2_base, current_rel_path)
        path1_data = list_files_and_directories(current_full_path1, token, base_url, refresh=use_refresh)
        path2_data = list_files_and_directories(current_full_path2, token, base_url, refresh=use_refresh)
        nodes = {}
        path2_copy = path2_data.copy()  
        for entry1 in path1_data:
            if interval > 0:
                sleep(interval)  
            match = None
            for entry2 in path2_copy:
                if entry2['name'] == entry1['name'] and entry2['is_dir'] == entry1['is_dir']:
                    match = entry2
                    break
            if match:
                node_path = os.path.join(current_rel_path, entry1['name']).replace('\\', '/')
                syncok = True
                is_dir = entry1['is_dir']
                unsynctype = 0
                size = entry1.get('size', 0)
                if not is_dir:  
                    size1 = entry1.get('size', 0)
                    size2 = match.get('size', 0)
                    if size1 != size2:
                        syncok = False
                        if size1 > size2:
                            unsynctype = 3
                        else:
                            unsynctype = 4
                    else:
                        unsynctype = 0
                else:  
                    unsynctype = 0
                node = DirectoryNode(
                    name=entry1['name'],
                    path=node_path,
                    is_dir=is_dir,
                    syncok=syncok,
                    unsynctype=unsynctype,
                    size=size
                )
                nodes[node.id] = node
                logger.debug("添加节点: ID=%s, 名称=%s, 路径=%s", node.id, node.name, node.path) 
                with lock:  
                    TOTAL_SCANNED += 1
                    if node.unsynctype == 0:
                        if node.is_dir: 
                            SYNC_DIRS += 1
                        else: 
                            SYNC_FILES += 1
                    elif node.unsynctype == 1:
                        MISSING_TARGET += 1
                    elif node.unsynctype == 2:
                        MISSING_SOURCE += 1
                    elif node.unsynctype in (3,4):
                        SIZE_DIFF += 1
                if is_dir and syncok:
                    child_rel_path = node_path
                    sub_nodes = build_tree(path1_base, path2_base, child_rel_path, interval=interval, use_refresh=use_refresh, max_depth=max_depth-1)
                    nodes.update(sub_nodes)
                    node.children = list(sub_nodes.values())
                    for child in node.children:
                        child.parent = node
                path2_copy.remove(match)
            else:
                node_path = os.path.join(current_rel_path, entry1['name']).replace('\\', '/')
                syncok = False
                unsynctype = 1
                is_dir = entry1['is_dir']
                size = entry1.get('size', 0)
                node = DirectoryNode(
                    name=entry1['name'],
                    path=node_path,
                    is_dir=is_dir,
                    syncok=syncok,
                    unsynctype=unsynctype,
                    size=size
                )
                nodes[node.id] = node
                logger.debug("添加节点: ID=%s, 名称=%s, 路径=%s", node.id, node.name, node.path)  
                with lock:  
                    TOTAL_SCANNED += 1
                    if node.unsynctype == 0:
                        if node.is_dir: 
                            SYNC_DIRS += 1
                        else: 
                            SYNC_FILES += 1
                    elif node.unsynctype == 1:
                        MISSING_TARGET += 1
                    elif node.unsynctype == 2:
                        MISSING_SOURCE += 1
                    elif node.unsynctype in (3,4):
                        SIZE_DIFF += 1
        for entry2 in path2_copy:
            node_path = os.path.join(current_rel_path, entry2['name']).replace('\\', '/')
            syncok = False
            unsynctype = 2
            is_dir = entry2['is_dir']
            size = entry2.get('size', 0)
            node = DirectoryNode(
                name=entry2['name'],
                path=node_path,
                is_dir=is_dir,
                syncok=syncok,
                unsynctype=unsynctype,
                size=size
            )
            nodes[node.id] = node
            logger.debug("添加节点: ID=%s, 名称=%s, 路径=%s", node.id, node.name, node.path)  
            with lock:  
                TOTAL_SCANNED += 1
                if node.unsynctype == 0:
                    if node.is_dir: 
                        SYNC_DIRS += 1
                    else: 
                        SYNC_FILES += 1
                elif node.unsynctype == 1:
                    MISSING_TARGET += 1
                elif node.unsynctype == 2:
                    MISSING_SOURCE += 1
                elif node.unsynctype in (3,4):
                        SIZE_DIFF += 1
        return nodes
    def update_compare_button_state():
        with lock:
            is_scanning = SCAN_IN_PROGRESS
        if not is_scanning:
            init_compare_button.config(state=tk.NORMAL)
        else:
            init_compare_button.config(state=tk.DISABLED)
    update_compare_button_state()
    status_frame = tk.Frame(root)
    status_frame.grid(row=2, column=0, sticky='ew')
    tk.Label(status_frame, text="扫描状态：").pack(side=tk.LEFT)
    scan_status = tk.StringVar(value="等待扫描")
    tk.Label(status_frame, textvariable=scan_status).pack(side=tk.LEFT)
    tk.Label(status_frame, text="    扫描操作总计数：").pack(side=tk.LEFT)
    scanned_count = tk.StringVar(value="0")
    tk.Label(status_frame, textvariable=scanned_count).pack(side=tk.LEFT)
    sync_files_var = tk.StringVar(value="0")
    sync_dirs_var = tk.StringVar(value="0")
    unsync_folders_var = tk.StringVar(value="0")
    missing_source_var = tk.StringVar(value="0")
    missing_target_var = tk.StringVar(value="0")
    size_diff_var = tk.StringVar(value="0")
    tk.Label(status_frame, text="  扫描结果总计数： 同步文件：").pack(side=tk.LEFT)
    tk.Label(status_frame, textvariable=sync_files_var).pack(side=tk.LEFT)
    tk.Label(status_frame, text="  同步目录：").pack(side=tk.LEFT)
    tk.Label(status_frame, textvariable=sync_dirs_var).pack(side=tk.LEFT)
    tk.Label(status_frame, text="  未同步文件夹：").pack(side=tk.LEFT)
    tk.Label(status_frame, textvariable=unsync_folders_var).pack(side=tk.LEFT)
    tk.Label(status_frame, text="  源缺失：").pack(side=tk.LEFT)
    tk.Label(status_frame, textvariable=missing_source_var).pack(side=tk.LEFT)
    tk.Label(status_frame, text="  目标缺失：").pack(side=tk.LEFT)
    tk.Label(status_frame, textvariable=missing_target_var).pack(side=tk.LEFT)
    tk.Label(status_frame, text="  大小不同：").pack(side=tk.LEFT)
    tk.Label(status_frame, textvariable=size_diff_var).pack(side=tk.LEFT)
    auto_sync_canceled = False  
    def show_auto_sync_dialog(parent, total_seconds, on_start_callback):
        dialog = tk.Toplevel(parent)
        dialog.title("自动同步提示")
        dialog.transient(parent)
        dialog.grab_set()  
        
        remaining_time = total_seconds
        time_var = tk.StringVar(value=f"自动同步将于{remaining_time}秒内开始执行。")
        
        label = tk.Label(dialog, textvariable=time_var)
        label.pack(pady=20)
        def update_time():
            nonlocal remaining_time
            if remaining_time > 0:
                remaining_time -= 1
                time_var.set(f"自动同步将于{remaining_time}秒内开始执行。")
                dialog.after(1000, update_time)
            else:
                on_start_callback()
                dialog.destroy()
        update_time()
        def on_immediate_start():
            dialog.destroy()
            on_start_callback()
        def on_cancel():
            nonlocal auto_sync_canceled
            auto_sync_canceled = True
            dialog.destroy()
        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="立即开始", command=on_immediate_start).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="取消", command=on_cancel).pack(side=tk.RIGHT, padx=5)  
        dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    def trigger_auto_sync():
        if not auto_sync_canceled:
            check_and_start_scan()
    auto_sync_mode = config.getboolean('task', 'auto_sync_mode', fallback=False)
    task_time = config.getint('task', 'sync_tasktime', fallback=0)
    if auto_sync_mode and task_time >= 0:
        task_seconds = task_time * 60 + 5
        show_auto_sync_dialog(root, task_seconds, trigger_auto_sync)
    root.mainloop()
if __name__ == "__main__":
    login_window()