# HITSZ Srun Login

MIT License, Copyright (c) 2025 PageChen04

更适合哈工深宝宝体质的深澜登录工具。现已支持 HIT SSO 登录。

## 使用方法

前往 [Releases](https://github.com/PageChen04/hitsz-srun-login/releases) 下载最新版。（[下载哪个文件？](https://github.com/MetaCubeX/mihomo/wiki/FAQ)）

```bash
./hitsz-srun-login -username <username> -password <password>
```

对应 HIT SSO 的登录账号和密码。

## 可能的报错

- `unexpected status code: 401 , maybe credential is not correct or captcha is required`
  - 账号密码错误
  - 需要滑动验证，可以在他处（例如[这里](https://ids.hit.edu.cn/authserver/login)）人工登录后再进行尝试
  - 账号风控（**已知登录累计并行会话数>10或IP数≥10，将被冻结**）
- `Login Result: {"code":1,"message":"","user_name":"","data":[]}
  - 该 IP 已登录
  - 账号套餐异常

## TODO

- [ ] 登出功能
- [ ] 储存 Cookie 以减少登录次数
- [ ] 支持选择网卡或出口 IP
- [ ] 支持传统登录方式
- [ ] 支持 Captcha
- [ ] 更好的错误提示

## 致谢

- [YinMo19/hit_course](https://github.com/YinMo19/hit_course) - 学习了其 HIT SSO 的登录代码
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) - 采用了其构建脚本
