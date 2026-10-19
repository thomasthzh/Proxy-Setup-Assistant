"""Native desktop wizard. Network work runs off the Tk thread; mutations need consent."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from .. import __version__
from ..cli import SetupError, private_write, state_root, validate_document
from . import downloads, environment, guidance, profiles

BG = "#f4f6f8"
INK = "#193042"
TEAL = "#096e65"
MUTED = "#526879"


def console_command(config: Path, *, ssh_only: bool = False) -> list[str]:
    if getattr(sys, "frozen", False):
        helper = Path(sys.executable).with_name("Proxy-Setup-Console.exe")
        if not helper.is_file():
            raise SetupError("缺少 Proxy-Setup-Console.exe；请把下载的 ZIP 完整解压后运行。")
        command = [str(helper)]
    else:
        interpreter = Path(sys.executable)
        if interpreter.name.lower() == "pythonw.exe":
            interpreter = interpreter.with_name("python.exe")
            if not interpreter.is_file():
                raise SetupError("没有找到支持交互式终端的 python.exe，请使用完整 Windows 发行包。")
        command = [str(interpreter), "-m", "vps_proxy_setup.desktop.console"]
    return command + ["--config", str(config)] + (["--ssh-only"] if ssh_only else [])


class Wizard:
    def __init__(self, root: tk.Tk, *, self_test: bool = False):
        self.root = root
        self.self_test = self_test
        self.expert = tk.BooleanVar(root, False)
        self.busy = False
        self.events: queue.Queue = queue.Queue()
        self.report = None
        self.assessments = ()
        self.pending_plan = None
        self.task = "local"
        self.page_name = "home"
        self.source = tk.StringVar(root)
        self.clash_dir = tk.StringVar(root, str(profiles.default_clash_dir()))
        self.clash_version = tk.StringVar(root)
        self.mihomo_version = tk.StringVar(root)
        self.profile_name = tk.StringVar(root, "我的代理")
        self.sourceforge = tk.BooleanVar(root, False)
        self.activation = tk.BooleanVar(root, True)
        self.status = tk.StringVar(root, "准备就绪 · 配置与凭据保留在本机")
        self.vps_values = {key: tk.StringVar(root, value) for key, value in {
            "host": "", "port": "22", "alias": "MyVPS", "address": "", "identity_file": "",
            "https": "8443", "hy2": "8443", "trojan": "9443", "email": "",
        }.items()}
        self.tailscale = tk.BooleanVar(root, False)
        self.acme = tk.BooleanVar(root, False)
        self.ssh_only = tk.BooleanVar(root, False)
        self.root.title("Proxy Setup Assistant · 代理配置助手")
        self.root.geometry("1060x790")
        self.root.minsize(880, 640)
        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=INK, font=("Microsoft YaHei UI", 10))
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 23, "bold"))
        style.configure("Sub.TLabel", foreground=MUTED)
        style.configure("TButton", padding=(14, 9), font=("Microsoft YaHei UI", 10))
        style.configure("Primary.TButton", background=TEAL, foreground="white")
        style.map("Primary.TButton", background=[("active", "#085c55"), ("disabled", "#7e9794")])
        style.configure("TCheckbutton", background=BG, font=("Microsoft YaHei UI", 10))
        style.configure("TRadiobutton", background=BG, font=("Microsoft YaHei UI", 11))
        style.configure("TEntry", padding=8, font=("Microsoft YaHei UI", 11))
        shell = ttk.Frame(root, padding=20)
        shell.pack(fill="both", expand=True)
        sidebar = ttk.Frame(shell, width=190)
        sidebar.pack(side="left", fill="y", padx=(0, 24))
        sidebar.pack_propagate(False)
        ttk.Label(sidebar, text="PROXY ASSIST", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(4, 4))
        ttk.Label(sidebar, text="让配置有路可循", style="Sub.TLabel").pack(anchor="w", pady=(0, 28))
        self.nav_buttons = []
        for name, label in (("home", "01   选择需求"), ("environment", "02   检测与安装"),
                            ("local", "03   导入本机订阅"), ("vps", "04   部署个人 VPS"), ("help", "05   使用与排障")):
            button = ttk.Button(sidebar, text=label, command=lambda n=name: self.navigate(n))
            button.pack(fill="x", pady=5)
            self.nav_buttons.append(button)
        ttk.Label(sidebar, text=f"v{__version__}\n开源 · 本地处理\n不代购套餐", style="Sub.TLabel", justify="left").pack(side="bottom", anchor="w", pady=12)
        right = ttk.Frame(shell)
        right.pack(side="left", fill="both", expand=True)
        self.canvas = tk.Canvas(right, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(right, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="top", fill="both", expand=True)
        self.body = ttk.Frame(self.canvas, padding=(4, 6, 18, 20))
        self.body_id = self.canvas.create_window((0, 0), anchor="nw", window=self.body)
        self.body.bind("<Configure>", lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda event: self.canvas.itemconfigure(self.body_id, width=event.width))
        self.root.bind("<MouseWheel>", self.wheel)
        self.progress = ttk.Progressbar(right, mode="indeterminate")
        self.progress.pack(side="bottom", fill="x", pady=(8, 0))
        ttk.Label(right, textvariable=self.status, style="Sub.TLabel", wraplength=680).pack(side="bottom", fill="x", pady=(10, 0))
        self.navigate("home")
        self.root.after(100, self.pump)
        if not self_test:
            self.root.after(250, self.initial_detection)

    def wheel(self, event):
        if not isinstance(event.widget, (tk.Text, tk.Listbox)):
            self.canvas.yview_scroll(-int(event.delta / 120), "units")

    def close(self):
        if self.busy:
            messagebox.showinfo("操作仍在进行", "请等待当前操作结束后关闭。", parent=self.root)
            return
        self.root.destroy()

    def heading(self, title, detail):
        ttk.Label(self.body, text=title, style="Title.TLabel").pack(anchor="w", pady=(0, 12))
        self.paragraph(detail, muted=True)

    def paragraph(self, text, *, muted=False):
        label = ttk.Label(self.body, text=text, justify="left", wraplength=690,
                          style="Sub.TLabel" if muted else "TLabel")
        label.pack(fill="x", anchor="w", pady=(0, 14))
        label.bind("<Configure>", lambda e: label.configure(wraplength=max(300, e.width)))
        return label

    def button(self, text, command, *, primary=False):
        button = ttk.Button(self.body, text=text, command=command, style="Primary.TButton" if primary else "TButton")
        button.pack(fill="x", pady=(0, 10))
        return button

    def field(self, label, variable, *, secret=False):
        ttk.Label(self.body, text=label).pack(anchor="w", pady=(0, 5))
        entry = ttk.Entry(self.body, textvariable=variable, show="•" if secret else "")
        entry.pack(fill="x", pady=(0, 14))
        return entry

    def check(self, label, variable):
        ttk.Checkbutton(self.body, text=label, variable=variable).pack(anchor="w", pady=(0, 14))

    def text_box(self, text, height=8):
        box = tk.Text(self.body, wrap="word", height=height, font=("Microsoft YaHei UI", 10),
                      bg="white", fg=INK, relief="flat", padx=14, pady=14)
        box.insert("1.0", text)
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, pady=(0, 16))
        return box

    def navigate(self, page):
        if self.busy:
            return
        self.page_name = page
        for child in self.body.winfo_children():
            child.destroy()
        self.canvas.yview_moveto(0)
        getattr(self, "show_" + page)()

    def _toggle(self, enabled):
        def walk(widget):
            for child in widget.winfo_children():
                if isinstance(child, (ttk.Button, ttk.Entry, ttk.Checkbutton, ttk.Radiobutton)):
                    child.configure(state="normal" if enabled else "disabled")
                walk(child)
        walk(self.body)
        for button in self.nav_buttons:
            button.configure(state="normal" if enabled else "disabled")

    def work(self, label, task, completed):
        if self.busy:
            return
        self.busy = True
        self.status.set(label)
        self._toggle(False)
        self.progress.start(12)

        def run():
            try:
                self.events.put((completed, task(), None))
            except Exception as error:
                # Workers may see private URLs. Never display arbitrary exception text.
                self.events.put((completed, None, error))
        threading.Thread(target=run, daemon=True).start()

    def pump(self):
        try:
            while True:
                completed, result, error = self.events.get_nowait()
                self.busy = False
                self.progress.stop()
                self._toggle(True)
                if error:
                    self.status.set("未完成；原有配置未被主动替换。请检查原因后重试。")
                    safe_types = (SetupError, downloads.DownloadError)
                    message = str(error) if isinstance(error, safe_types) else "操作失败，请检查网络、文件权限或软件版本后重试。"
                    messagebox.showerror("需要处理", message, parent=self.root)
                else:
                    self.status.set("操作完成")
                    completed(result)
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(100, self.pump)

    def remember_environment(self, report):
        self.report = report
        versions = [getattr(app, "version", None) for app in report.proxy_apps
                    if app.key in ("clash_verge_rev", "clash_verge")]
        if versions and versions[0]:
            self.clash_version.set(versions[0].lstrip("v"))
        if getattr(report, "mihomo_version", None):
            self.mihomo_version.set(report.mihomo_version.lstrip("v"))

    def initial_detection(self):
        def done(report):
            self.remember_environment(report)
            self.status.set(f"已检测：{report.os_name} / {report.architecture} · {len(report.proxy_apps)} 个可能的代理客户端")
        self.work("正在只读检测本机环境…", environment.detect_environment, done)

    def show_home(self):
        self.heading("你想从哪里开始？", "从当前环境出发，完成一件事。你可以随时返回，已填写的信息会保留到本次运行结束。")
        ttk.Radiobutton(self.body, text="我是新人，希望一步一步指引", variable=self.expert, value=False).pack(anchor="w", pady=8)
        ttk.Radiobutton(self.body, text="我是老手，有明确需求", variable=self.expert, value=True).pack(anchor="w", pady=(8, 24))
        self.button("1. 个人服务器（VPS）代理一键配置", lambda: self.choose("vps"), primary=True)
        self.paragraph("已有 VPS：配置本地 SSH 密钥，再部署代理、国内直连规则和私人导入页面。", muted=True)
        self.button("2. 本机配置代理", lambda: self.choose("local"), primary=True)
        self.paragraph("已有订阅链接或配置文件：检查客户端、导入订阅并配置国内直连。没有订阅也可以从这里开始。", muted=True)

    def choose(self, task):
        self.task = task
        self.navigate(task if self.expert.get() else "environment")

    def show_environment(self):
        self.heading("先看看这台电脑", "检测不会卸载软件或更改系统代理。便携版、改名程序和未登记的软件可能无法识别。")
        if self.report:
            lines = [f"系统：{self.report.os_name} / {self.report.architecture}",
                     "OpenSSH：" + ("已安装" if self.report.ssh_path else "未发现；VPS 部署需要 Windows 可选功能中的 OpenSSH 客户端")]
            if not self.report.proxy_apps:
                lines.append("未检测到代理软件。可以帮助你下载并安装 Clash Verge Rev。")
            for app in self.report.proxy_apps:
                lines.append(f"• {app.name} {getattr(app, 'version', None) or ''} — {'运行中' if app.running else '已登记'}")
            self.text_box("\n".join(lines), 7)
        else:
            self.paragraph("尚未检测环境。点击下方按钮开始。")
        self.button("重新检测环境，并查询项目维护状态", self.scan)
        if self.assessments:
            lines = []
            installed = {app.key for app in self.report.proxy_apps} if self.report else set()
            for item in self.assessments:
                if item.key not in installed:
                    continue
                state = "已归档，项目停止接收常规维护" if item.archived else ("仓库可访问，未归档" if item.status == "available" else "未能确认当前维护状态")
                license_name = item.license_spdx or "开源许可证未确认"
                lines.append(f"{item.repository}\n{state} · {license_name}\n最新发布：{item.latest_release or '未知'} / {item.published_at or '未知'}")
            if lines:
                self.text_box("\n\n".join(lines), 8)
            self.paragraph("仓库未归档不代表安全保证；查询失败也不等于停止维护。无法区分的 Clash Verge 版本请在软件“关于”中核对。", muted=True)
        self.check("也比较 SourceForge 第三方镜像（仍须匹配官方 SHA-256）", self.sourceforge)
        self.button("帮助我下载、校验 Clash Verge Rev 安装包", self.prepare_download, primary=True)
        self.button("我想移除旧软件：打开系统应用管理", self.uninstall_help)
        self.button("继续：" + ("填写 VPS 信息" if self.task == "vps" else "配置本机订阅"), lambda: self.navigate(self.task))

    def scan(self):
        def task():
            return environment.detect_environment(), environment.assess_projects()
        def done(result):
            self.remember_environment(result[0])
            self.assessments = result[1]
            self.navigate("environment")
        self.work("正在检测客户端、查询官方项目状态…", task, done)

    def uninstall_help(self):
        if messagebox.askyesno("由你选择卸载对象", "要打开 Windows 已安装应用页面吗？\n请先在旧客户端备份订阅和规则，再自行选择要卸载的软件。助手不会自动删除任何客户端。", parent=self.root):
            if not environment.open_windows_apps_settings():
                messagebox.showinfo("手动打开", "请打开系统设置 → 应用 → 已安装的应用。", parent=self.root)

    def prepare_download(self):
        report = self.report or environment.detect_environment()
        self.remember_environment(report)
        if report.os_name != "Windows":
            messagebox.showinfo("当前平台", "自动安装目前支持 Windows。请从官方发布页选择本机安装包。", parent=self.root)
            webbrowser.open("https://github.com/clash-verge-rev/clash-verge-rev/releases/latest")
            return
        allow_mirror = self.sourceforge.get()
        def task():
            note = "已取得官方最新稳定版信息。"
            try:
                installer = downloads.get_latest_installer(report.architecture)
            except downloads.DownloadError:
                installer = downloads.get_pinned_installer(report.architecture)
                note = "无法查询最新版本；使用 2026-10-19 已核验的 v2.5.8 固定版本。"
            return installer, downloads.probe_candidates(installer, allow_sourceforge=allow_mirror), note
        self.work("正在获取官方发行信息并比较可用线路…", task, self.download_ready)

    def download_ready(self, data):
        installer, candidates, note = data
        if installer.version.lstrip("v") not in profiles.SUPPORTED_CLASH_VERSIONS:
            messagebox.showinfo("客户端版本已更新", "官方发布了更新版本，但本版助手尚未验证其导入格式。请先更新助手，避免安装后不能导入。", parent=self.root)
            return
        usable = [item for item in candidates if not item.error]
        if not usable:
            messagebox.showerror("没有可用线路", "所选线路均未通过 HTTPS 检查。可以稍后重试、允许第三方镜像，或从官方发布页手动下载。", parent=self.root)
            return
        best = usable[0]
        measured = "\n".join(f"{item.label}: {'不可用' if item.error else str(round(item.bytes_per_second / 1024)) + ' KiB/s'}" for item in candidates)
        text = f"{note}\n版本：{installer.version} / {installer.architecture}\n大小：{installer.size / 1024**2:.1f} MiB\n\n{measured}\n\n将下载本次探测较快的线路，完成后核对官方 SHA-256。现在下载吗？"
        if not messagebox.askyesno("确认下载", text, parent=self.root):
            return
        self.work("正在下载并校验安装包，速度取决于当前网络…",
                  lambda: downloads.download_installer(installer, state_root() / "downloads", best), self.install_ready)

    def install_ready(self, path):
        if messagebox.askyesno("安装包校验通过", "是否打开安装程序？\n请按安装向导操作，首次打开 Clash Verge Rev 后退出它，再回到助手导入配置。\n\n" + str(path), parent=self.root):
            try:
                os.startfile(str(path))
            except OSError:
                messagebox.showerror("未能启动", "请在下载目录手动打开已校验的安装包。", parent=self.root)
        self.status.set("安装包已校验。安装完成后点击“重新检测环境”。")

    def show_local(self):
        self.heading("你是否已有订阅？", "可以粘贴私人 HTTPS 链接，或选择 Clash / Mihomo YAML 配置。内容只在本机处理，不经过第三方转换服务。")
        self.field("订阅链接或文件路径（隐藏显示）", self.source, secret=True)
        self.button("选择本地 YAML / JSON 配置文件…", self.browse_subscription)
        self.button("我没有订阅：查看获取方式与流量估算", lambda: self.navigate("referrals"))
        self.field("在 Clash Verge Rev 中显示的名称", self.profile_name)
        self.field("Clash Verge Rev 配置目录", self.clash_dir)
        self.field("客户端版本（自动识别失败时，从“关于”中填写）", self.clash_version)
        self.field("Mihomo 内核版本（当前已验证 1.19.32；文件导入可留空）", self.mihomo_version)
        self.paragraph("首次安装请先启动客户端一次，再从托盘彻底退出。导入只支持已核对配置格式的 2.5.8；其他版本会明确阻止写入。", muted=True)
        self.button("检查订阅并预览配置计划", self.preview_subscription, primary=True)
        self.paragraph("默认策略：国内及内网直连，其他流量走 PROXY；保留 URL 订阅更新。导入会新增独立配置，并备份原配置索引。", muted=True)

    def browse_subscription(self):
        selected = filedialog.askopenfilename(parent=self.root, filetypes=[("Clash 配置", "*.yaml *.yml *.json"), ("所有文件", "*")])
        if selected:
            self.source.set(selected)

    def preview_subscription(self):
        source = self.source.get().strip()
        directory = Path(self.clash_dir.get().strip()).expanduser()
        version = self.clash_version.get().strip()
        core_version = self.mihomo_version.get().strip()
        name = self.profile_name.get().strip()
        if not source or not version:
            messagebox.showinfo("还缺少信息", "请输入订阅链接或文件，并确认 Clash Verge Rev 版本。", parent=self.root)
            return
        def task():
            subscription = profiles.load_subscription(source)
            return profiles.preview_import(subscription, directory, clash_version=version, profile_name=name, mihomo_version=core_version)
        def done(plan):
            self.pending_plan = plan
            self.navigate("preview")
        self.work("正在读取订阅并生成导入计划…", task, done)

    def show_preview(self):
        self.heading("确认这次配置", "核对完成后再写入。请从托盘退出 Clash Verge Rev，以免正在运行的客户端覆盖文件。")
        plan = self.pending_plan
        if plan is None:
            self.button("返回订阅输入", lambda: self.navigate("local"))
            return
        self.text_box(plan.summary, 13)
        if plan.conflicts:
            self.paragraph("请先在客户端处理以下冲突，再退出客户端并重新预览：\n" + "\n".join(plan.conflicts))
            self.button("返回修改并重新检查", lambda: self.navigate("local"), primary=True)
            return
        self.check("同时将新配置设为当前配置（不会自动开启系统代理）", self.activation)
        self.button("确认导入，并备份现有配置索引", self.apply_subscription, primary=True)
        self.button("返回修改", lambda: self.navigate("local"))

    def apply_subscription(self):
        plan = self.pending_plan
        activate = self.activation.get()
        if not messagebox.askyesno("最后确认", "请确认客户端已彻底退出。\n助手将新增订阅与国内直连扩展，备份原配置索引。现在写入吗？", parent=self.root):
            return
        def done(result):
            self.pending_plan = None
            self.source.set("")
            self.last_backup = result.backup_dir
            self.result_text = result.message + "\n备份位置：" + str(result.backup_dir)
            self.navigate("complete")
        self.work("正在备份并写入配置…", lambda: profiles.apply_import(plan, consent=True, activate=activate), done)

    def show_complete(self):
        self.heading("配置已写入，接下来验证连接", "重新打开 Clash Verge Rev，选择刚导入的配置，使用规则模式，再按需打开系统代理。")
        self.text_box(getattr(self, "result_text", ""), 5)
        self.paragraph("第一次启动需下载国内规则集。若下载失败，先检查客户端日志和网络；不要直接切换为全局模式。打开一个国内网站和一个境外网站，在“连接”中分别确认 DIRECT 与 PROXY。")
        self.button("规则、策略组和 TUN 是什么？", lambda: self.navigate("help"), primary=True)
        if getattr(self, "last_backup", None):
            self.button("撤销本次导入（客户端需退出）", self.rollback)
        self.button("再配置一台 VPS 或另一份订阅", lambda: self.navigate("home"))

    def rollback(self):
        if messagebox.askyesno("撤销本次导入", "将恢复导入前的配置索引，并移除本次新增的配置。若客户端或文件已有后续变化，会停止回滚。现在继续吗？", parent=self.root):
            def done(_):
                self.last_backup = None
                self.result_text = "本次导入已撤销，原配置索引已恢复。"
                self.navigate("complete")
            self.work("正在核对备份并撤销本次导入…", lambda: profiles.rollback_import(self.last_backup, consent=True), done)

    def show_referrals(self):
        self.heading("获取一份订阅", "你可以使用任何服务商，也可以返回部署自己的 VPS。")
        self.paragraph("还没有用量记录？先选支持短期使用的小套餐，正常用 7 天，再看服务商账单里的已用流量。开着代理不等于一直耗流量，不必按每天在线多久买大套餐。")
        self.paragraph("下方为仓库作者提供的推广入口，含推荐码；可访问不代表服务质量或套餐背书。注册与购买由你在浏览器完成。", muted=True)
        self.button("检测四个推广入口的 HTTPS 可达性", self.probe_referrals, primary=True)
        self.button("已有用量记录：换算每月用量", lambda: self.navigate("usage_estimate"))
        self.button("高级：计算持续直播或下载用量", lambda: self.navigate("bitrate_estimate"))
        self.button("我已有订阅，返回导入", lambda: self.navigate("local"))
        self.button("我想自己部署 VPS", lambda: self.navigate("vps"))

    def show_usage_estimate(self):
        self.heading("用实际记录，选合适套餐", "优先填服务商账单的已用流量；客户端记录需覆盖同一时段及所有参与统计的设备。")
        self.paragraph("只统计计入这个套餐的流量。国内直连通常不消耗代理套餐；服务商的计费倍率以账单为准。", muted=True)
        if not hasattr(self, "usage_total"):
            self.usage_total = tk.StringVar(self.root)
            self.usage_period = tk.StringVar(self.root, "7")
            self.usage_unit = tk.StringVar(self.root, "天")
            self.usage_people = tk.StringVar(self.root, "1")
            self.usage_result = tk.StringVar(self.root, "填好后点击换算。不会额外加算余量。")
        self.field("这段时间已用的总流量（GB）", self.usage_total)
        self.field("统计时长", self.usage_period)
        ttk.Combobox(self.body, textvariable=self.usage_unit, state="readonly", values=("天", "个月")).pack(fill="x", pady=(0, 14))
        self.field("这份总流量由几个人使用（自己用填 1）", self.usage_people)
        self.button("换算每月用量", self.estimate_observed_traffic, primary=True)
        ttk.Label(self.body, textvariable=self.usage_result, wraplength=680).pack(fill="x", pady=(0, 14))
        self.paragraph("短期记录只适合初步参考，包含平常使用习惯的完整月份更可靠。多人结果是平均值，不表示每个人用量一样；长时间直播或大文件下载需另算。", muted=True)
        self.button("返回获取订阅", lambda: self.navigate("referrals"))

    def estimate_observed_traffic(self):
        try:
            unit = {"天": "days", "个月": "months"}[self.usage_unit.get()]
            value = guidance.observed_monthly_traffic(
                self.usage_total.get(), self.usage_period.get(), self.usage_people.get(), unit=unit)
            basis = "按 30 天折算" if unit == "days" else "按统计月份平均"
            result = f"全组约 {value.group_gb:,.1f} GB/月 · 人均约 {value.per_person_gb:,.1f} GB/月（{basis}）。"
            if value.group_gb == 0:
                result += "\n这段时间没有记录到流量，不能据此判断下个月不需要流量。"
            else:
                result += "\n按这个记录选接近的套餐档位，再留少量余量；用量变化后再调整。"
            self.usage_result.set(result)
        except (KeyError, SetupError):
            self.usage_result.set("请填写有效记录：总流量可为 0，时长至少 1 天或 1 个月，人数为 1–10000 的整数。")

    def show_bitrate_estimate(self):
        self.heading("持续传输用量（高级）", "适用于已知码率的持续直播、视频或下载，不用于按日常在线时长推荐套餐。")
        if not hasattr(self, "bitrate"):
            self.bitrate = tk.StringVar(self.root)
            self.hours = tk.StringVar(self.root)
            self.estimate = tk.StringVar(self.root, "仅计算实际持续经过代理的传输时段；待机、暂停和国内直连不计入。")
        self.field("传输期间的平均合计码率（Mbps，上传 + 下载）", self.bitrate)
        self.field("每天实际持续传输时长（小时）", self.hours)
        self.button("计算持续传输用量", self.estimate_traffic, primary=True)
        ttk.Label(self.body, textvariable=self.estimate, wraplength=680).pack(fill="x", pady=(0, 14))
        self.paragraph("计算式：Mbps × 每天传输小时 × 30 天 × 0.45 = GB/月。未加余量；服务商的计费倍率、协议开销和实际码率变化可能影响账单。", muted=True)
        self.button("返回获取订阅", lambda: self.navigate("referrals"))

    def estimate_traffic(self):
        try:
            value = guidance.monthly_traffic(float(self.bitrate.get()), float(self.hours.get()), reserve=1)
            self.estimate.set(f"仅上述持续传输约 {value:,.1f} GB/月（30 天，未加余量），不代表日常月用量。")
        except (ValueError, SetupError):
            self.estimate.set("请输入有效的正数：每天最多 24 小时，码率单位 Mbps。")

    def probe_referrals(self):
        def done(results):
            self.referral_results = results
            self.navigate("links")
        self.work("仅检查公开页面 HTTPS 连通性，不注册、不付款…", guidance.check_referrals, done)

    def show_links(self):
        self.heading("选择能访问的入口", "以下均含推广推荐码。注册、购买和套餐核对请自行在浏览器完成；不要在助手中输入账户密码。")
        for item in getattr(self, "referral_results", ()):
            label = item.url.split("/#/")[0]
            self.paragraph(label + "\n" + item.message + (f" · {item.seconds:.2f}s" if item.seconds is not None else ""))
            if item.reachable:
                self.button("在浏览器打开这个推广入口", lambda url=item.url: webbrowser.open(url))
        self.paragraph("若全部不可达，请稍后重试或自行选择其他服务商。助手不会绕过证书错误，也不会推荐不安全的 HTTP 入口。", muted=True)
        self.button("已取得订阅：返回导入", lambda: self.navigate("local"), primary=True)
        self.button("返回获取订阅", lambda: self.navigate("referrals"))

    def show_vps(self):
        self.heading("部署你的个人 VPS", "适用于全新 Debian 12/13、Ubuntu 22.04/24.04。使用 root 登录；密码交给系统 OpenSSH 输入，不保存到助手。")
        self.paragraph("商家端口带冒号时请拆开填写：地址填 IP，SSH 端口填冒号后的数字。代理公网入口可以不同于 SSH / Tailscale 地址。", muted=True)
        for key, label in (("host", "SSH 地址（IP 或主机名）"), ("port", "SSH 端口"),
                           ("alias", "SSH 别名（以后可执行 ssh MyVPS）"), ("address", "代理公网 IPv4 或域名（仅配置 SSH 时可留空）")):
            self.field(label, self.vps_values[key])
        if self.expert.get():
            for key, label in (("identity_file", "已有私钥路径（留空创建专用密钥）"),
                               ("https", "订阅页面 TCP 端口"), ("hy2", "Hysteria 2 UDP 端口"),
                               ("trojan", "Trojan TCP 备用端口"), ("email", "证书联系邮箱（可留空）")):
                self.field(label, self.vps_values[key])
        else:
            self.paragraph("默认端口：TCP 80、8443、9443；UDP 8443。需在商家防火墙开放。NAT VPS 还需对应端口映射；可回首页切换老手模式修改端口。")
        self.check("安装 Tailscale（部署后需在浏览器登录授权）", self.tailscale)
        self.check("仅配置 SSH，不部署代理", self.ssh_only)
        self.check("我同意 Let's Encrypt 服务条款，用于申请 HTTPS 证书", self.acme)
        self.button("查看证书服务条款", lambda: webbrowser.open("https://letsencrypt.org/repository/"))
        self.button("检查参数并开始部署", self.start_vps, primary=True)

    def vps_document(self):
        values = {key: var.get().strip() for key, var in self.vps_values.items()}
        address = ("vps.example.com" if self.ssh_only.get() else values["address"] or values["host"])
        return validate_document({"ssh": {key: values[key] for key in ("host", "port", "alias", "identity_file")},
                                  "server": {"address": address, "email": values["email"],
                                             "ports": {key: values[key] for key in ("https", "hy2", "trojan")},
                                             "tailscale": self.tailscale.get(), "tune": True,
                                             "acme_accept_terms": self.acme.get() or self.ssh_only.get()}})

    def start_vps(self):
        try:
            if hasattr(self, "console_process") and self.console_process.poll() is None:
                raise SetupError("已有部署终端在运行，请先完成它，避免重复部署。")
            document = self.vps_document()
            if not (self.report or environment.detect_environment()).ssh_path:
                raise SetupError("请先在 Windows 设置 → 可选功能安装 OpenSSH 客户端，再重新检测环境。")
            ssh_only = self.ssh_only.get()
            ports = document["server"]["ports"]
            action = "配置 SSH 密钥和别名" if ssh_only else f"配置 SSH、安装代理及 HTTPS 页面。\n需要 TCP 80/{ports['https']}/{ports['trojan']}，UDP {ports['hy2']}。"
            if not messagebox.askyesno("确认部署目标", f"目标：{document['ssh']['host']}:{document['ssh']['port']}\n将{action}\n\n接下来打开终端：首次请核对服务器指纹，再输入密码。", parent=self.root):
                return
            config = state_root() / document["ssh"]["alias"] / "desktop-request.json"
            command = console_command(config, ssh_only=ssh_only)
            options = {"creationflags": subprocess.CREATE_NEW_CONSOLE} if os.name == "nt" else {}
            if os.name != "nt":
                raise SetupError("图形启动交互式 SSH 目前支持 Windows。请在终端运行 vps-proxy-setup --config 配置路径。")
            self.console_result = state_root() / document["ssh"]["alias"] / "result.json"
            self.console_result_old = self.console_result.stat().st_mtime_ns if self.console_result.exists() else None
            private_write(config, json.dumps(document, ensure_ascii=False, indent=2) + "\n")
            self.console_process = subprocess.Popen(command, **options)
            self.status.set("部署终端已打开；请在终端完成 SSH 验证与密码输入。")
            self.root.after(1000, self.poll_console)
        except SetupError as error:
            messagebox.showerror("检查参数", str(error), parent=self.root)
        except (OSError, ValueError):
            messagebox.showerror("无法启动", "无法保存请求或启动部署终端，请检查解压是否完整及文件权限。", parent=self.root)

    def poll_console(self):
        if self.console_process.poll() is None:
            self.root.after(1000, self.poll_console)
            return
        self.status.set("部署终端已结束；请以终端输出的部署及入口验证结果为准。")
        try:
            if self.console_result.exists() and self.console_result.stat().st_mtime_ns != self.console_result_old:
                result = json.loads(self.console_result.read_text(encoding="utf-8"))
                if result.get("status") == "ready" and str(result.get("base_url", "")).startswith("https://"):
                    if messagebox.askyesno("服务器返回导入入口", "是否在浏览器打开本次部署生成的私人导入页面？\n该地址含访问凭据，请勿公开。", parent=self.root):
                        webbrowser.open(result["base_url"])
        except (OSError, ValueError):
            pass

    def show_help(self):
        self.heading("配置完成后，怎么用？", "先掌握规则模式、策略组和系统代理，再按需开启 TUN。")
        self.text_box(guidance.HELP_TEXT, 24)
        self.button("返回首页", lambda: self.navigate("home"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="VPS Proxy Setup 桌面向导")
    parser.add_argument("--self-test", action="store_true", help="仅检查图形页面与依赖，不连接网络或修改配置")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    root = tk.Tk()
    wizard = Wizard(root, self_test=args.self_test)
    if args.self_test:
        for page in ("home", "environment", "local", "referrals", "usage_estimate", "bitrate_estimate", "links", "vps", "preview", "complete", "help"):
            wizard.navigate(page)
            root.update()
        wizard.expert.set(True)
        wizard.navigate("vps")
        root.update()
        root.destroy()
        return 0
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
