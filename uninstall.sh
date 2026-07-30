#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo ./uninstall.sh 运行。" >&2
  exit 1
fi

systemctl disable --now wallpilot-web.service wallpilot-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/wallpilot-web.service
rm -f /etc/systemd/system/wallpilot-agent.service
systemctl daemon-reload

echo "WallPilot 服务和程序单元已移除。"
echo "/opt/wallpilot 与 /var/lib/wallpilot 未自动删除，以保留程序、备份、回收站和审计记录。"
echo "确认不再需要后，请由管理员手动归档或删除这两个明确目录。"

