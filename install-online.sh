#!/bin/sh
set -eu

REPOSITORY="${WALLPILOT_REPOSITORY:-Zzsv/wallpilot}"
REF="${WALLPILOT_REF:-main}"
ARCHIVE_SHA256="${WALLPILOT_ARCHIVE_SHA256:-}"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo 运行 WallPilot 在线安装程序。" >&2
  exit 1
fi

case "$REPOSITORY" in
  ""|*[!A-Za-z0-9._/-]*|/*|*/|*..*)
    echo "WALLPILOT_REPOSITORY 格式无效。" >&2
    exit 1
    ;;
esac

case "$REF" in
  ""|*[!A-Za-z0-9._/-]*|/*|*/|*..*)
    echo "WALLPILOT_REF 格式无效。" >&2
    exit 1
    ;;
esac

if ! command -v tar >/dev/null 2>&1; then
  echo "在线安装需要 tar。" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/wallpilot-install.XXXXXX")"
archive="$work_dir/wallpilot.tar.gz"
source_dir="$work_dir/source"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

archive_url="https://codeload.github.com/$REPOSITORY/tar.gz/$REF"
echo "正在从 https://github.com/$REPOSITORY 下载 WallPilot（$REF）……"

if command -v curl >/dev/null 2>&1; then
  curl --fail --location --silent --show-error \
    --proto '=https' --tlsv1.2 \
    --output "$archive" "$archive_url"
elif command -v wget >/dev/null 2>&1; then
  wget --https-only --quiet --output-document="$archive" "$archive_url"
else
  echo "在线安装需要 curl 或 wget。" >&2
  exit 1
fi

if [ -n "$ARCHIVE_SHA256" ]; then
  case "$ARCHIVE_SHA256" in
    *[!A-Fa-f0-9]*)
      echo "WALLPILOT_ARCHIVE_SHA256 必须是64位十六进制摘要。" >&2
      exit 1
      ;;
  esac
  if [ "${#ARCHIVE_SHA256}" -ne 64 ]; then
    echo "WALLPILOT_ARCHIVE_SHA256 必须是64位十六进制摘要。" >&2
    exit 1
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "校验安装包需要 sha256sum。" >&2
    exit 1
  fi
  printf '%s  %s\n' "$ARCHIVE_SHA256" "$archive" | sha256sum --check --status
  echo "安装包 SHA-256 校验通过。"
fi

mkdir "$source_dir"
tar -xzf "$archive" -C "$source_dir" --strip-components=1

if [ ! -f "$source_dir/install.sh" ]; then
  echo "下载内容中没有 install.sh，已停止安装。" >&2
  exit 1
fi

cd "$source_dir"
sh ./install.sh
