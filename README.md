# HITSZ Srun Login

MIT License, Copyright (c) 2026 PageChen04.

更适合哈工深宝宝体质的深澜校园网登录工具。现已支持 HIT SSO 登录。

## 使用方法

前往 [Releases](https://github.com/PageChen04/hitsz-srun-login/releases) 下载最新版。（[下载哪个文件？](https://github.com/MetaCubeX/mihomo/wiki/FAQ)）

```console
./hitsz-srun-login -username <username> -password <password> [-bind <bind_ip>] [-dry-run] [-session-file <path>] [-no-session] [-non-interactive] [-mfa-method <sms|app|email|otp>] [-mfa-code <code>] [-otp-secret <secret>]
```

参数替换成对应 HIT SSO 的登录账号和密码；如果未通过参数指定，程序会在终端里交互询问。若指定 `-non-interactive`，则缺失的账号、密码、MFA 方式或 MFA 验证码都会直接报错退出，读取 stdin 时遇到 EOF 也同样报错退出。程序会默认将会话 Cookie 保存到系统缓存目录，下次运行时优先复用已有会话，并在启动时打印实际使用的 session 文件路径；也可以通过 `-session-file` 指定持久化文件路径，或通过 `-no-session` 禁用会话持久化。

如果账号触发多步认证，程序会自动进入 MFA 流程：

- 默认交互式输出可用认证方式代号，并提示输入对应代号
- 对 `sms`、`app`、`email` 会先自动发送验证码，再提示输入
- 对 `otp` 会直接提示输入令牌
- 也可以通过 `-mfa-method` 和 `-mfa-code` 预先传入，避免交互
- 当 `-mfa-method otp` 且未指定 `-mfa-code` 时，如果传入 `-otp-secret`，程序会本地生成当前 OTP

## 可能的报错

- `unexpected status code: 401 , maybe credential is not correct or captcha is required`
  - 账号密码错误
  - 需要滑动验证，可以在他处（例如[这里](https://ids.hit.edu.cn/authserver/login)）人工登录后再进行尝试
  - 账号风控（**已知登录累计并行会话数>10或IP数≥10，将被冻结**）
- `Login Result: {"code":1,"message":"","user_name":"","data":[]}`
  - 该 IP 已登录
  - 账号套餐异常
  - 其他奇怪的深澜内部问题

## TODO

- [ ] 登出功能
- [X] 储存 Cookie 以减少登录次数
- [X] 支持选择网卡或出口 IP
- [ ] 支持传统登录方式
- [ ] 支持 Captcha
- [ ] 更好的错误提示
- [ ] 更多校园网信息提示

## 致谢

- [YinMo19/hit_course](https://github.com/YinMo19/hit_course) - 学习了其 HIT SSO 的登录代码
- [Zjl37/idshit.py](https://github.com/Zjl37/idshit.py) - 学习了其 HIT SSO 的多步认证代码
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) - 采用了其构建脚本
