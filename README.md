# LaunchOS 2.1.1 注册机完整流程

## 文件

```text
launchos_2_1_1_tool.py           patch + 本地注册机一体脚本
launchos_keygen_work/private.pem JWT 私钥
launchos_keygen_work/public.pem  JWT 公钥，会复制进 App
```

## 一键 patch

```bash
python3 /Users/yaozaiyu/Downloads/LaunchOS-Keygen-Final/launchos_2_1_1_tool.py patch
```

脚本会做：

1. 检查 App 版本必须是 `2.1.1(302)`
2. 把 API 改到 `127.0.0.1:8765`
3. 替换 `/Applications/LaunchOS.app/Contents/Resources/public.pem`
4. patch 响应签名失败分支
5. `xattr -cr`
6. `codesign --force --deep --sign -`

## patch 点

2.1.1 响应签名失败分支：

```text
文件：/Applications/LaunchOS.app/Contents/MacOS/LaunchOS
VA：0x10005771c
文件偏移：0x65771c
原字节：b4000036
新字节：1f2003d5
```

含义：

```asm
tbz w20, #0x0, 0x100057730
```

改成：

```asm
nop
```

用于绕过：

```text
network error: si ...
```

## 启动注册机服务

```bash
python3 /Users/yaozaiyu/Downloads/LaunchOS-Keygen-Final/launchos_2_1_1_tool.py serve
```

正常输出：

```text
LaunchOS keygen server listening on http://127.0.0.1:8765
```

## 激活

1. 启动注册机服务。
2. 打开 `/Applications/LaunchOS.app`。
3. 输入任意邮箱和许可证。
4. 点击激活。

也可以一条命令先 patch 再启动服务：

```bash
python3 /Users/yaozaiyu/Downloads/LaunchOS-Keygen-Final/launchos_2_1_1_tool.py all
```

## 验证

```bash
defaults read app.remixdesign.LaunchOS
```

重点字段：

```text
IsActivated = 1
IsPro = 1
```
