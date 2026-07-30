# Security Policy

请不要在公开Issue中粘贴真实防火墙规则、访问路径、会话、TOTP密钥、服务器IP
或诊断包。安全问题请通过GitHub Security Advisory的私密报告入口提交。

WallPilot `0.x` 仍处于早期阶段。生产部署应满足：

- 管理服务只监听回环地址；
- 使用SSH隧道或可信内网；
- 服务器保留云控制台或带外恢复方式；
- 定期安装WallPilot及其Python依赖的安全更新；
- 在每次升级后重新运行测试机上的防锁死演练。

