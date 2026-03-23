# HITSZ Srun Login

MIT License, Copyright (c) 2026 PageChen04.

更适合哈工深宝宝体质的深澜校园网登录工具。现已支持 HIT SSO 登录。

## 使用方法

前往 [Releases](https://github.com/PageChen04/hitsz-srun-login/releases) 下载最新版。（[下载哪个文件？](https://github.com/MetaCubeX/mihomo/wiki/FAQ)）

最简单用法：

```console
./hitsz-srun-login
```

程序会优先复用本地已保存的会话；如果需要重新登录，则在终端里交互询问账号、密码和可能的 MFA 信息。

无人值守用法：

```console
./hitsz-srun-login -non-interactive -username <username> -password <password> -mfa-method otp -otp-secret <secret>
```

常用示例：

```console
./hitsz-srun-login -username <username> -password <password>
./hitsz-srun-login -username <username> -password <password> -dry-run
./hitsz-srun-login -non-interactive -username <username> -password <password>
./hitsz-srun-login -non-interactive -username <username> -password <password> -mfa-method otp -otp-secret <secret>
```

参数：

- `-username <username>`: HIT SSO 用户名。未指定时按需交互输入。
- `-password <password>`: HIT SSO 密码。未指定时按需交互输入。
- `-bind <bind_ip>`: 绑定出口 IP 或网卡对应 IP。
- `-dry-run`: 只完成 HIT SSO，不执行最终校园网登录。

- `-session-file <path>`: 指定持久化会话文件路径。
- `-no-session`: 禁用会话读取和保存。

- `-non-interactive`: 非交互式操作。若缺少账号、密码、MFA 方式或 MFA 验证码，则直接报错退出；读取 stdin 时遇到 EOF 也同样直接退出。
- `-mfa-method <sms|app|email|otp>`: 指定 MFA 方式。
- `-mfa-code <code>`: 指定 MFA 验证码或 OTP。
- `-otp-secret <secret>`: 当 `-mfa-method otp` 且未指定 `-mfa-code` 时，在本地生成当前 OTP。

- `-no-remember-sso`: 关闭 SSO 的 `rememberMe`。
- `-no-remember-mfa`: 关闭 MFA 的 `skipTmpReAuth`。

MFA 行为：

- 默认交互式输出可用认证方式代号，并提示输入对应代号。
- 对 `sms`、`app`、`email` 会先自动发送验证码，再提示输入
- 对 `otp` 会直接提示输入令牌。
- 也可以通过 `-mfa-method` 和 `-mfa-code` 预先传入，避免交互。
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
