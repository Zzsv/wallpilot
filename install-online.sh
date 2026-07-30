#!/bin/sh
set -eu

REPOSITORY="${WALLPILOT_REPOSITORY:-Zzsv/wallpilot}"
VERSION="${WALLPILOT_VERSION:-0.1.0}"
REF="${WALLPILOT_REF:-}"
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

case "$VERSION" in
  ""|v*|*[!A-Za-z0-9._-]*|*..*)
    echo "WALLPILOT_VERSION 格式无效；请使用不带 v 的版本号。" >&2
    exit 1
    ;;
esac

if ! command -v tar >/dev/null 2>&1; then
  echo "在线安装需要 tar。" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/wallpilot-install.XXXXXX")"
source_dir="$work_dir/source"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

download() {
  destination="$1"
  url="$2"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --silent --show-error \
      --proto '=https' --tlsv1.2 \
      --output "$destination" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget --https-only --quiet --output-document="$destination" "$url"
  else
    echo "在线安装需要 curl 或 wget。" >&2
    exit 1
  fi
}

if [ -n "$REF" ]; then
  case "$REF" in
    *[!A-Za-z0-9._/-]*|/*|*/|*..*)
      echo "WALLPILOT_REF 格式无效。" >&2
      exit 1
      ;;
  esac
  if [ -z "$ARCHIVE_SHA256" ]; then
    echo "使用 WALLPILOT_REF 时必须同时提供 WALLPILOT_ARCHIVE_SHA256。" >&2
    exit 1
  fi
  archive_name="wallpilot-custom.tar.gz"
  archive_url="https://codeload.github.com/$REPOSITORY/tar.gz/$REF"
  expected_sha256="$ARCHIVE_SHA256"
  echo "正在下载 WallPilot 自定义版本（$REF）……"
else
  archive_name="wallpilot-$VERSION.tar.gz"
  archive_url="https://github.com/$REPOSITORY/releases/download/v$VERSION/$archive_name"
  checksum_url="$archive_url.sha256"
  checksum_file="$work_dir/$archive_name.sha256"
  echo "正在下载 WallPilot v$VERSION 正式发布包……"
fi

archive="$work_dir/$archive_name"
download "$archive" "$archive_url"

if [ -z "$REF" ]; then
  download "$checksum_file" "$checksum_url"
  expected_sha256=""
  checksum_name=""
  read -r expected_sha256 checksum_name < "$checksum_file"
  if [ "$checksum_name" != "$archive_name" ]; then
    echo "安装包校验文件与当前版本不匹配。" >&2
    exit 1
  fi
fi

case "$expected_sha256" in
  *[!A-Fa-f0-9]*)
    echo "安装包 SHA-256 摘要格式无效。" >&2
    exit 1
    ;;
esac
if [ "${#expected_sha256}" -ne 64 ]; then
  echo "安装包 SHA-256 摘要格式无效。" >&2
  exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "校验安装包需要 sha256sum。" >&2
  exit 1
fi
actual_sha256="$(sha256sum "$archive")"
actual_sha256="${actual_sha256%% *}"
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "安装包 SHA-256 校验失败，已停止安装。" >&2
  exit 1
fi
echo "安装包 SHA-256 校验通过。"

mkdir "$source_dir"
tar -xzf "$archive" -C "$source_dir" --strip-components=1

if [ ! -f "$source_dir/install.sh" ]; then
  echo "下载内容中没有 install.sh，已停止安装。" >&2
  exit 1
fi

cd "$source_dir"
sh ./install.sh
