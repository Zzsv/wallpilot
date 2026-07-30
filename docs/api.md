# HTTP API

所有路径都位于随机前缀 `/manage/<secret>/api/v1` 下。除初始化、登录和认证状态
外均需要会话Cookie；所有修改请求还需要 `X-CSRF-Token`。

## 读取

- `GET /system/status`
- `GET /system/metrics`
- `GET /firewall/status`
- `GET /firewall/rules`
- `GET /firewall/objects`
- `GET /firewall/objects/{type}/{name}`
- `GET /firewall/logs`
- `GET /recycle-bin`
- `GET /backups`
- `GET /audit`
- `GET /diagnostics`
- `GET /export`

## 修改

- `POST /firewall/service-action`
- `POST /drafts`
- `POST /batch-delete`
- `POST /import`
- `POST /drafts/{id}/confirm`
- `POST /apply-sessions/{id}/confirm`
- `POST /apply-sessions/{id}/rollback`
- `POST /recycle-bin/{id}/restore`
- `POST /recycle-bin/batches/{batch_id}/restore`
- `POST /recycle-bin/{id}/purge`
- `POST /recycle-bin/batches/{batch_id}/purge`
- `POST /backups`

规则、高级对象和批量操作使用同一固定状态机：

```text
pending draft → applying runtime → pending confirmation
                                   ├─ confirmed
                                   └─ rolled_back / rollback_failed
```

服务关闭和禁用也会创建待确认应用会话。

`GET /export` 返回 `wallpilot-config` 版本1文档，可原样提交到 `POST /import`。
导入会跳过内容完全相同的项目，并拒绝同名但内容不同的高级对象。
