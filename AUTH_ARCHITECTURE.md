# MoDi Downloader 身份与授权边界

## 当前路径

HTTP 下载、Range 分片、文件落盘和续传只依赖 `ITunneledHttpClientPool`；不读取身份来源，也不改变网络路由。应用启动时由 `ConnectionIdentityProviderFactory` 按本地设置选择 `IConnectionIdentityProvider`，再把已验证的 `SshConnectionProfile` 交给 SSH 隧道层。

- `PrivateIdentityProvider` 是当前私人版提供者。固定云端配置和 known-hosts 指纹由 `PrivateBuildIdentity` 提供；私有构建可把加密私钥作为程序集资源注入。口令只从 Windows Credential Manager 读取，首次解锁时由用户在本机遮罩输入框提供并保存。程序设置、清单、日志和报告不保存口令或私钥内容。
- `IPrivatePassphraseStore` 隔离口令来源，`WindowsCredentialVault` 是 Windows 实现。私人授权撤销只清理本机凭据并断开本机隧道，不声称能撤销或终止服务端已建立的 SSH 会话。
- `CloudApprovedIdentityProvider` 和 `ICloudDeviceAuthorizationClient` 是未来协议边界。当前没有客户端或云端服务实现时一律返回 `NotConfigured` / 明确失败；不生成伪造设备、审批状态或 SSH 凭据。配置源通过 `ConnectionIdentityProviderKind` 选择。

## 未来协议模型

`DeviceIdentity` 的 `DeviceId` 应由随机持久设备身份或设备公钥指纹派生；MAC 地址不是凭证。`DeviceRegistrationRequest` 包含公钥与 `ProofOfPossession`，服务端必须验证请求者持有对应私钥。`DeviceAccessRequest` 包含申请 ID、创建时间、有效期、审批状态、错误码及可展示原因。`ConnectionCredentialStatus` 和 `ServerConnectionConfiguration` 分离授权有效期与服务连接信息。

当前合法审批迁移由 `DeviceApprovalStateMachine` 限定：Pending 可变为 Approved、Rejected、Expired 或 Revoked；Approved 可被撤销；Rejected、Expired、Revoked 为终态。Windows 与 Android 的 MoDi Monitor 未来应调用同一云端管理 API，管理员身份与权限由服务器验证，不能信任客户端声明。

## 未来云端部署约束

- 设备首次注册时在本机生成并保留私钥；普通注册/审批 API 只接收公钥和签名挑战，不上传私钥。
- 每台设备使用独立身份与独立下载中转账号/等效隔离；服务端只允许所需的 TCP 动态转发，禁用 Shell、TTY 和不必要文件访问。
- 服务端需限制代理目标，阻止访问云主机本机、内网和云平台元数据地址；审核注册、申请、批准、拒绝、撤销操作并留审计记录。
- 删除授权公钥本身不一定中止已有 SSH 连接。云端撤销必须由服务器侧短期凭证、连接强制关闭或等效机制保证在有界时间内生效。
- MoDi Monitor 可消费待审批事件、展示申请详情并发起批准/拒绝/单设备撤销；API 服务端负责管理员鉴权。当前不修改 MoDi Monitor、不部署服务、不开放端口。
