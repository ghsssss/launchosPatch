# LaunchOS 注册机完整流程

## 文件

```text
launchos_2_1_3_tool.py           patch + 本地注册机一体脚本
launchos_keygen_work/private.pem JWT 私钥
launchos_keygen_work/public.pem  JWT 公钥，会复制进 App
```

## 一键 patch

```bash
python3 /Users/yaozaiyu/launchosPatch/launchos_2_1_3_tool.py patch
```

脚本会做：
1. 读取当前 App 版本并输出
2. 动态定位 arm64 响应签名失败分支偏移
3. 把 API 改到 `127.0.0.1:8765`
4. 替换 `/Applications/LaunchOS.app/Contents/Resources/public.pem`
5. patch 响应签名失败分支
6. `xattr -cr`
7. `codesign --force --deep --sign -`

## patch 点

响应签名失败分支不再写死版本偏移。脚本会动态查找：

```text
1. 读取 fat Mach-O 的 arm64 slice offset
2. 用 otool 找到 "network error: si " 附近的 stringCompareWithSmolCheck
3. 定位其后的 tbz/nop 指令
4. 通过 Mach-O __TEXT segment 把 VA 转成文件偏移
```

patch 含义：

```asm
tbz w20, #0x0, 0x10006307c
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
python3 /Users/yaozaiyu/launchosPatch/launchos_2_1_3_tool.py serve
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
python3 /Users/yaozaiyu/launchosPatch/launchos_2_1_3_tool.py all
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
