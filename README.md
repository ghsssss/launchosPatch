# LaunchOS 注册机完整流程

## 文件

```text
launchos_tool.py           patch + 本地注册机一体脚本
launchos_keygen_work/private.pem JWT 私钥
launchos_keygen_work/public.pem  JWT 公钥，会复制进 App
```

## 一键 patch

```bash
sudo python3 /Users/yaozaiyu/launchosPatch/launchos_2_1_3_tool.py all
```

## 激活

1. 启动注册机服务。
2. 打开 `/Applications/LaunchOS.app`。
3. 输入任意邮箱和许可证。
4. 点击激活。
5. 关闭 python 脚本


## 验证

```bash
defaults read app.remixdesign.LaunchOS
```

重点字段：

```text
IsActivated = 1
IsPro = 1
```
