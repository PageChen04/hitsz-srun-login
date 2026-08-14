# HITSZ Srun Login

MIT License, Copyright (c) 2026 PageChen04.

更适合哈工深宝宝体质的深澜校园网登录工具。现已支持 HIT SSO、本地账号登录、注销、在线设备查询与下线。

## 使用方法

前往 [Releases](https://github.com/DustinChen04/hitsz-srun-login/releases) 下载最新版。（[下载哪个文件？](https://github.com/MetaCubeX/mihomo/wiki/FAQ)）

查看用法：

```console
./hitsz-srun-login
```

一般，程序会尽多复用本地保存的会话，只在必要时在终端里交互询问账号、密码等信息。无人值守时，可加 `-non-interactive` 参数并用参数传递各种必要信息。

## 常用命令

```console
./hitsz-srun-login login           # HIT SSO 统一身份认证登录
./hitsz-srun-login local-login     # 深澜本地账号登录（本地用户名 + 密码）
./hitsz-srun-login logout          # 注销当前设备的上网认证
./hitsz-srun-login list-devices    # 列出账号下已认证的设备
./hitsz-srun-login kick-device     # 下线指定设备（-id 与 -mac，来自 list-devices）
```

### login —— HIT SSO 统一身份认证

```console
./hitsz-srun-login login -username <username> -password <password>
./hitsz-srun-login login -username <username> -password <password> -dry-run
./hitsz-srun-login login -non-interactive -username <username> -password <password> -mfa-method otp -otp-secret <secret>
```

程序会优先复用本地已保存的会话；如果需要重新登录，则在终端里交互询问账号、密码和可能的 MFA 信息。

参数：

- `-username <username>`: HIT SSO 用户名。未指定时按需交互输入。
- `-password <password>`: HIT SSO 密码。未指定时按需交互输入。
- `-bind <bind_ip>`: 绑定出口 IP 或网卡对应 IP。
- `-dry-run`: 只完成 HIT SSO，不执行最终校园网登录。

- `-mfa-method <sms|app|email|otp>`: 指定 MFA 方式。
- `-mfa-code <code>`: 指定 MFA 验证码或 OTP。
- `-otp-secret <secret>`: 当 `-mfa-method otp` 且未指定 `-mfa-code` 时，在本地生成当前 OTP。

- `-no-remember-sso`: 关闭 SSO 的 `rememberMe`。
- `-remember-mfa`: 将当前 CLI 登记为可信 MFA 设备。首次登录仍需完成 MFA，之后使用同一设备凭据登录时可跳过 MFA。
- `-mfa-device-file <path>`: 指定可信 MFA 设备凭据文件。Windows 默认保存在当前设备的 LocalAppData 中；Linux 和 macOS 默认保存在用户配置目录中。
- `-no-remember-mfa`: 不登记可信 MFA 设备；覆盖 `-remember-mfa`，并保留用于兼容旧命令。

MFA 行为：

- 默认交互式输出可用认证方式代号，并提示输入对应代号。
- 对 `sms`、`app`、`email` 会先自动发送验证码，再提示输入；对 `otp` 会直接提示输入令牌。
- 也可以通过 `-mfa-method` 和 `-mfa-code` 预先传入，避免交互。
- 当 `-mfa-method otp` 且未指定 `-mfa-code` 时，如果传入 `-otp-secret`，程序会本地生成当前 OTP。

可信设备登录：

```console
./hitsz-srun-login login -remember-mfa
```

首次运行会生成一个随机设备标识，调用 HIT 的浏览器指纹登记接口，并在 MFA 成功后将其绑定为可信设备。以后继续使用 `-remember-mfa` 和同一设备文件时，HIT SSO 可跳过 MFA。设备文件具有绕过 MFA 的能力，应像密码一样妥善保管，不要提交到 Git 或发送给他人；删除文件后，还应在 HIT 账号的可信设备列表中移除对应记录。Linux 和 macOS 会拒绝读取权限宽于 `0600` 的设备文件；Windows 默认路径依赖 LocalAppData 目录继承的 ACL，自定义路径时请确保仅当前用户可读。

### local-login —— 深澜本地账号登录

```console
./hitsz-srun-login local-login -username <local_username> -password <local_password>
```

另一种上网认证方式，仅需本地用户名和密码。无本地账号的同学只能使用 `login`。

参数：

- `-username <username>`: 本地账号用户名。
- `-password <password>`: 本地账号密码。
- `-ip <ip>`: 指定要认证的 IP（默认由服务器根据请求来源自动识别）。

### logout —— 注销当前设备

```console
./hitsz-srun-login logout
```

### list-devices —— 列出认证设备

```console
./hitsz-srun-login list-devices
./hitsz-srun-login list-devices -username <local_username> -password <local_password>
```

列出账号下所有已认证设备（ID、IP、MAC、登录时间、产品、时长）。此功能需访问自助服务，可能需要本地账号登录，无本地账号的同学请先尝试用 login 一次再试。

### kick-device —— 下线指定设备

```console
./hitsz-srun-login kick-device -id <rad_online_id> -mac <mac>
./hitsz-srun-login kick-device -username <local_username> -password <local_password> -id <rad_online_id> -mac <mac>
```

`-id` 与 `-mac` 来自 `list-devices` 的输出，两者均必填。请确认下线的是目标设备。此功能亦需访问自助服务。

## 通用参数

所有子命令均支持：

- `-session-file <path>`: 指定持久化会话文件路径。
- `-no-session`: 禁用会话读取和保存。
- `-non-interactive`: 非交互式操作。若缺少账号、密码、验证码等，则直接报错退出；读取 stdin 时遇到 EOF 也同样直接退出。

## 可能的报错

- `unexpected status code: 401 , maybe credential is not correct or captcha is required`
  - 账号密码错误
  - 需要滑动验证，可以在他处（例如[这里](https://ids.hit.edu.cn/authserver/login)）人工登录后再进行尝试
  - 账号风控（**已知登录累计并行会话数>10或IP数≥10，将被冻结**）
- `Login Result: {"code":1,"message":"","user_name":"","data":[]}`
  - 该 IP 已登录
  - 账号套餐异常
  - 其他奇怪的深澜内部问题
- `validate-user failed: 验证码不能为空。` 或 `Portal login failed: self-service login requires a captcha`
  - 登录自助服务一般需要图形验证码，此时程序会将验证码图片保存到临时目录并提示输入。非交互模式下也可用 `-captcha` 直接传入再次运行同样的命令。

## TODO

- [X] 登出功能
- [X] 储存 Cookie 以减少登录次数
- [X] 支持选择网卡或出口 IP
- [X] 支持传统登录方式（本地账号）
- [X] 支持 Captcha（自助服务登录）
- [ ] 更好的错误提示
- [ ] 更多校园网信息提示

## 致谢

- [YinMo19/hit_course](https://github.com/YinMo19/hit_course) - 学习了其 HIT SSO 的登录代码
- [Zjl37/idshit.py](https://github.com/Zjl37/idshit.py) - 学习了其 HIT SSO 的多步认证代码
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) - 采用了其构建脚本
