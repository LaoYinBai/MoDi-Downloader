# MoDi Downloader 身份与授权边界

## 数据路径与构建版型

下载引擎、Range 分片和文件落盘只依赖 `ITunneledHttpClientPool`。它不调用身份 API，也没有本地直连 fallback。身份提供者只有在返回已验证的 SSH profile 后，桌面应用才会交给隧道管理器。

- Shared 构建由编译版型固定选择 `CloudApprovedIdentityProvider`，不能通过用户设置切换成私人身份。设备 ID 是 128 位 CSPRNG 值的 `mdp-` Base32 表示，仅用于标识，不构成认证。
- Windows shared 构建在 `%LOCALAPPDATA%/MoDiDownloader/identity` 保存 CurrentUser DPAPI 保护的设备 P-256 私钥，以及公开设备元数据。API 签名和 SSH.NET 通过短期内存流使用密钥；不会落地明文私钥路径。DPAPI 不防御同一 Windows 用户权限下的恶意软件或运行时内存检查。
- Shared 构建只有在用户点击“申请使用”后才登记设备并提交访问申请。所有状态检查经过 HTTPS API 和设备签名；Pending、Rejected、Expired、Revoked、NotConfigured、NetworkUnavailable 都不会产生 SSH profile。Pending 和临时 API 故障复用现有连接生命周期每 15 秒检查一次。
- 私人构建通过独立的 `MoDiPrivateBuild=true` 构建参数选择 `PrivateIdentityProvider`。固定私人 SSH 身份资源仅能从构建机指定的私有路径注入，并且不进入普通 Shared Release。口令留在 Windows Credential Manager。用户设置不会改变构建版型。
- `CloudDeviceAuthorizationOptions` 从 `MODI_AUTH_API_BASE_URL`、`MODI_AUTH_RELAY_HOST`、`MODI_AUTH_RELAY_PORT`、`MODI_AUTH_RELAY_USERNAME` 和分号分隔的 `MODI_AUTH_RELAY_HOST_FINGERPRINTS` 读取非秘密配置。默认值为空；API 或中继缺失/不合规时返回 NotConfigured。生产客户端使用系统 TLS 证书验证，禁止自动 HTTP 重定向，设定连接与总请求超时、16 KiB 响应上限和有限重试。
- `MODI_DOWNLOADER_DATA_DIRECTORY` 可为隔离测试或高级本机配置覆写设置/DPAPI 身份根目录；未设置时仍使用 Windows LocalAppData 下的 `MoDiDownloader`。

## 签名与服务端职责

设备使用其 P-256 密钥证明持有权。服务端 v1 协议对每个受保护请求使用一次性、设备绑定 challenge，签名覆盖 `MODI-AUTH-DEVICE-V1` 域、规范化请求方法/路径/查询、原始请求体 SHA-256、nonce 和 Unix 时间戳；ECDSA 签名使用 SHA-256 与 RFC 3279 DER 格式。重试重新取得 challenge，并复用同一个申请幂等键。

服务端审批记录永久保留；审批后不下发有期限的 bearer token。每台设备的公钥只获准访问专用下载中继账号。中继只开放必须的本地 TCP 转发，禁止 Shell、TTY 和不必要文件访问，并在实际 direct-tcpip 路径限制回环、私网、链路本地和云元数据目标。

API 与本地中继配置没有配置好时，下载器明确显示不可用且绝不直接下载。`DownloadManager` 仍只从 SSH 隧道池取得 HTTP 客户端，身份 API 不承担文件数据流量。

## 本机移除与管理员撤销

下载器中的“移除此机身份”会暂停下载、断开本机隧道、删除当前安装的 DPAPI 设备身份和本地申请 ID；它**不调用**服务端 revoke API，也不删除服务端批准记录。设备若再次申请会生成新密钥和 `mdp-` ID；旧的服务端批准记录仍由 MoDi Monitor 管理员单独撤销。

Monitor 是独立的管理员客户端：它用 Android Keystore 管理管理员签名密钥，轮询待审批事件并提交签名批准、拒绝和撤销。服务端验证管理员公钥权限并记录审计事件，绝不因请求来自 Monitor 而默认可信。

服务端撤销会阻止该设备后续 SSH 认证，但仅移除公钥不一定终止已建立的 TCP 转发连接。现行协议不承诺有界时间强制结束既有会话；客户端断开或服务端另行实现经过验证的连接关闭机制后，活动隧道才会结束。

本仓库只实现 Windows 客户端边界，不修改 MoDi Monitor，不部署服务，不开放端口。当前服务器端 API / HTTPS 中继配置尚未部署，因此实际云端申请、审批通知和真实 SSH 中继验收仍未验证。
