#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo ./install.sh 运行安装程序。" >&2
  exit 1
fi

if [ ! -d /run/systemd/system ]; then
  echo "当前系统未运行 systemd；WallPilot 服务控制不可安装。" >&2
  exit 1
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo "WallPilot 需要 Python 3.10 或更高版本。" >&2
  exit 1
}

if ! getent group wallpilot >/dev/null 2>&1; then
  groupadd --system wallpilot
fi
if ! id wallpilot >/dev/null 2>&1; then
  useradd --system --gid wallpilot --home-dir /var/lib/wallpilot \
    --shell /usr/sbin/nologin wallpilot
fi

install -d -o root -g root -m 0755 /opt/wallpilot
install -d -o wallpilot -g wallpilot -m 0700 /var/lib/wallpilot

"$PYTHON_BIN" -m venv /opt/wallpilot/venv
/opt/wallpilot/venv/bin/python -m pip install --upgrade pip
/opt/wallpilot/venv/bin/python -m pip install .

install -o root -g root -m 0644 deploy/wallpilot-agent.service \
  /etc/systemd/system/wallpilot-agent.service
install -o root -g root -m 0644 deploy/wallpilot-web.service \
  /etc/systemd/system/wallpilot-web.service

systemctl daemon-reload
systemctl enable --now wallpilot-agent.service wallpilot-web.service

echo
echo "WallPilot 已安装，Web只监听 127.0.0.1:8787。"
echo "请保存下面的一次性初始化信息："
echo
runuser -u wallpilot -- env WALLPILOT_STATE_DIR=/var/lib/wallpilot \
  /opt/wallpilot/venv/bin/wallpilot bootstrap
echo
echo "客户端隧道示例：ssh -L 8787:127.0.0.1:8787 user@server"

