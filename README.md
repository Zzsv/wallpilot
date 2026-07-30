# WallPilot

WallPilot 是一个面向个人 Linux 服务器的防火墙与状态管理面板。它把常用的
firewalld 和 UFW 操作整理成中文 Web 界面，同时把防误操作、自动回滚、删除
恢复和权限隔离放在功能之前。

> 当前版本是 `0.1.0`。请先在测试机或可通过云控制台恢复的服务器上验证，再用
> 于生产环境。WallPilot 只管理本机防火墙，不会修改云安全组、路由器或负载均衡器。

## 核心能力

- 识别 Ubuntu、Debian、RHEL、Rocky、AlmaLinux、Fedora、openSUSE、Arch
  及其版本和 `ID_LIKE` 系列。
- 以实际活动状态选择 firewalld、UFW、nftables 或 iptables；多个后端同时
  活动时自动进入只读模式。
- firewalld 运行时规则使用系统 D-Bus；区域、策略、自定义服务和 IPSet 使用
  官方 `firewall-cmd` D-Bus 客户端的固定参数接口。支持来源、协议、源端口、
  ICMP、masquerade、区域内转发、端口转发、优先级和富规则。
- UFW 支持 allow、deny、reject、limit、来源、目标、接口、路由和 IPv4/IPv6
  规则；所有调用都是 `shell=False` 的参数数组。
- nftables 与旧版 iptables 提供规则查看和严格白名单内的服务控制。
- 开启、关闭、重启、reload、开机启用和取消开机启用防火墙。
- 删除规则需要两次确认；删除成功后才写入带校验和的回收站。
- 变更先试运行，90 秒内没有确认就自动回滚。关闭防火墙也适用该机制。
- 支持多选批量删除、按删除批次整体恢复，以及经过同一回滚流程的 JSON
  批量导入导出。
- 支持 UFW 逐规则日志、路由规则和重启后仍有效的临时规则到期任务；firewalld
  使用原生运行时 timeout。
- 展示系统、CPU负载、内存、磁盘、网络、监听端口、容器、关键安全服务和告警。
- 展示网卡地址、默认路由、DNS、活动连接、SSH 会话、SELinux/AppArmor、
  inode、容器端口映射和最近一小时拒绝日志。
- 保存最近24小时采样、配置备份、不可从界面删除的审计记录及脱敏诊断快照。

## 安全默认值

- Web 只监听 `127.0.0.1:8787`，安装程序不会开放防火墙端口。
- 入口包含本机生成的256位随机路径；未知路径直接返回404。
- 随机路径不是认证机制，仍强制使用管理员密码和TOTP。
- Web进程以普通 `wallpilot` 用户运行；root代理只监听Unix Socket。
- 代理请求使用HMAC签名并校验调用用户，方法和服务单元均使用白名单。
- 密码使用Argon2id；会话只保存令牌哈希，并启用CSRF、Host/Origin校验、
  HttpOnly、SameSite、CSP和登录限速。
- 不加载CDN、外部字体、外部脚本，也不会把服务器数据上传到互联网。

完整边界见 [威胁模型](docs/threat-model.md)。

## 安装

要求：

- Python 3.10 或更高版本
- systemd
- firewalld 或 UFW；nftables/iptables 可只读使用
- root 权限仅用于安装和运行受限代理

```bash
git clone <你的 WallPilot 仓库地址>
cd wallpilot
sudo ./install.sh
```

安装完成后会显示一次初始化信息。也可以重新查看：

```bash
sudo -u wallpilot \
  WALLPILOT_STATE_DIR=/var/lib/wallpilot \
  /opt/wallpilot/venv/bin/wallpilot bootstrap
```

在自己的电脑建立SSH隧道：

```bash
ssh -L 8787:127.0.0.1:8787 user@server
```

然后打开安装程序显示的随机管理地址。初始化时把TOTP密钥加入身份验证器，
使用引导令牌、管理员密码和动态码完成设置。页面会显示八个一次性恢复码，请
离线保存；恢复码只能用于登录，不能代替永久清除时要求的TOTP。

## 防锁死流程

1. 在界面创建变更草稿。
2. 检查端口、来源、区域、影响和风险。
3. 输入页面生成的六位二次确认码。
4. 高风险操作还需TOTP与主机名。
5. WallPilot保存配置快照并应用试运行规则。
6. 在90秒内确认连接正常，才持久化普通规则；否则自动执行逆操作。

firewalld 的 `--new-zone`、`--new-policy`、`--new-service` 和 `--new-ipset`
只提供永久配置接口，因此新建高级对象会以“可逆永久暂存”方式执行：先保存完整
快照并创建对象，90秒未确认时由看门狗删除或还原该对象。这个限制不会绕过二次
确认、TOTP、主机名确认或回滚。

如果网页无法访问，可从服务器控制台执行：

```bash
sudo WALLPILOT_STATE_DIR=/var/lib/wallpilot \
  /opt/wallpilot/venv/bin/wallpilot emergency-start

sudo WALLPILOT_STATE_DIR=/var/lib/wallpilot \
  /opt/wallpilot/venv/bin/wallpilot emergency-rollback
```

## 回收站

- 规则从运行时和永久配置删除并确认成功后，才会进入回收站。
- 快照包含后端、系统版本、对象指纹、完整配置、删除前状态、操作者和原因。
- 数据库记录与独立JSON快照都带HMAC校验；校验失败时恢复会被拒绝。
- 恢复也必须经过二次确认和90秒试运行。
- 相同规则已经存在时不会重复添加。
- 区域、策略、服务和 IPSet 会保存完整配置、引用关系和 SHA-256 原始配置哈希；
  同名不同内容时拒绝覆盖，缺少依赖时拒绝恢复。
- 支持多选删除后按批次整体恢复；批次中的回收项共享批次编号。
- 永久清除要求管理员密码、TOTP和“永久删除”确认文字。
- 永久清除不会删除审计事件。

## 本地命令

```text
wallpilot bootstrap
wallpilot status [--json]
wallpilot serve
wallpilot rotate-path
wallpilot emergency-start
wallpilot emergency-rollback
```

轮换随机路径后需要重启Web服务：

```bash
sudo systemctl restart wallpilot-web.service
```

## 开发

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
pytest
wallpilot bootstrap
wallpilot serve
```

非Linux开发环境使用临时状态目录，防火墙操作应注入测试适配器。测试覆盖系统
识别、后端冲突、参数验证、认证、恢复码、CSRF、代理签名、二次确认、临时规则、
批量导入删除、数据库损坏保护、回收站校验和恢复。

## 项目状态与边界

- firewalld 的自定义区域、策略、服务和 IPSet 均可在图形界面创建、编辑、
  删除和恢复；系统内置对象保持只读。
- 原生nftables表达式非常灵活，首版不会尝试重写用户已有ruleset。
- Web只允许控制防火墙服务，其他systemd服务只读。
- 当前仓库的自动测试使用适配器和固定命令响应，不会在开发机执行破坏性防火墙
  操作。生产部署前仍应在一次性 Ubuntu、Debian、Rocky 和 Fedora 虚拟机中运行
  真实集成验收。
- 公网直连不是默认部署方式。如确需公网访问，必须在可信反向代理后启用HTTPS，
  设置 `WALLPILOT_COOKIE_SECURE=1` 和精确的 `WALLPILOT_ALLOWED_HOSTS`。

## 许可

[MIT](LICENSE)
