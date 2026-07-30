# HTTP API

所有路径都位于随机前缀 `/manage/<secret>/api/v1` 下。除初始化、登录和认证状态
外均需要会话Cookie；所有修改请求还需要 `X-CSRF-Token`。

## 读取

- `GET /system/status`
- `GET /system/metrics`
- `GET /firewall/status`
- `GET /firewall/rules`
- `GET /recycle-bin`
- `GET /backups`
- `GET /audit`
- `GET /diagnostics`
- `GET /export`

## 修改

- `POST /firewall/service-action`
- `POST /drafts`
- `POST /drafts/{id}/confirm`
- `POST /apply-sessions/{id}/confirm`
- `POST /apply-sessions/{id}/rollback`
- `POST /recycle-bin/{id}/restore`
- `POST /recycle-bin/{id}/purge`
- `POST /backups`

写规则的固定状态机为：

```text
pending draft → applying runtime → pending confirmation
                                   ├─ confirmed
                                   └─ rolled_back / rollback_failed
```

服务关闭和禁用也会创建待确认应用会话。

