# LaunchOS patch + 本地注册机流程

## 文件说明

```text
launchos_tool.py              一体脚本：patch / serve / all
launchos_keygen_work/private.pem  本地服务签 JWT 的私钥
launchos_keygen_work/public.pem   会复制进 App 的公钥
```

## 常用命令

进入目录：

```bash
cd /path/to/launchosPatch
```

一键 patch 并启动本地服务：

```bash
sudo python3 /path/to/launchosPatch/launchos_tool.py all
```

脚本启动 `serve/all` 前会自动清理占用 `8765` 的旧进程。

## patch 做了什么

1. 读取当前 LaunchOS 版本。
2. 动态定位响应签名校验失败分支，不写死版本偏移。
3. 把 API 地址替换到 `127.0.0.1:8765`。
4. 把 `launchos_keygen_work/public.pem` 复制到 App 资源目录。
5. `xattr -cr` 清扩展属性。
6. `codesign --force --deep --sign -` 重新签名。

核心 patch：

```text
b4000036 -> 1f2003d5
tbz      -> nop
```

用于绕过响应签名校验失败分支：

```text
network error: si ...
```

## 激活

1. 确保本地服务正在运行：

   ```text
   LaunchOS keygen server listening on http://127.0.0.1:8765
   ```

2. 打开 `/Applications/LaunchOS.app`。
3. 输入任意邮箱和许可证。
4. 点击激活。

## 权限问题

如果报：

```text
PermissionError: [Errno 1] Operation not permitted:
'/Applications/LaunchOS.app/Contents/MacOS/LaunchOS'
```

先确认：

1. LaunchOS 已完全退出。
2. 使用 `sudo` 执行 patch。
3. 给 Terminal 或 iTerm 开启：

```text
System Settings -> Privacy & Security -> Full Disk Access
```

开启后完全退出 Terminal/iTerm，再重新打开执行：

```bash
sudo python3 /path/to/launchosPatch/launchos_tool.py all
```

## 使用副本 App

脚本支持用 `LAUNCHOS_APP` 指定 App 路径，例如先 patch 一个副本：

```bash
sudo cp -R /Applications/LaunchOS.app /path/to/LaunchOS-copy.app
sudo LAUNCHOS_APP=/path/to/LaunchOS-copy.app python3 /path/to/launchosPatch/launchos_tool.py patch
open /path/to/LaunchOS-copy.app
python3 /path/to/launchosPatch/launchos_tool.py serve
```

## 验证

```bash
defaults read <bundle-id>
```

重点字段：

```text
IsActivated = 1
IsPro = 1
```

## 提交

```bash
cd /path/to/launchosPatch
git add launchos_tool.py README.md
git commit -m "更新 LaunchOS patch 流程"
```
