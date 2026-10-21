# MoDi Downloader 身份与授权

## 共享版流程

共享版只使用 CloudApprovedIdentityProvider。首次运行在本机生成 mdp- 加 128 位随机 Base32 设备 ID，并生成独立的 ECDSA P-256 SSH 密钥。私钥 DER 仅以 Windows CurrentUser DPAPI 保护形式写入 %LOCALAPPDATA%\MoDiDownloader\device-identity.json；签名和 SSH.NET 使用时短暂解密到进程内存。设备 ID、公钥、指纹、申请 ID 和幂等键不是凭据。

用户点击“申请使用下载器”后，客户端向 https://auth.modiconnect.cn/ 注册公钥并创建访问申请。每个 API 操作先获取一次性 challenge，再以 MODI-AUTH-DEVICE-V1 规范化请求、SHA-256 body hash 和 ECDSA DER 签名。API 只收公钥，不接收私钥。待批准状态每 15 秒检查；收到 Approved 后才创建 modi-relay SSH profile。Pending、Rejected、Expired、Revoked、网络错误均不会创建 SSH 身份，也不会让 HTTP 下载回退到本地网络。

获批后文件 HTTP/HTTPS 与动态分片仍只使用既有 SSH.NET SOCKS5 通道；公网域名 API 仅处理设备注册、申请和状态，不代理下载流量。SSH 主机密钥使用固定 pin。下载文件始终直接写入用户本机。

每台设备只保存自己的 DPAPI 设备私钥；共享安装包不嵌入管理员 SSH 私钥、设备私钥或云端口令。DPAPI 不防护同一 Windows 用户权限下的恶意软件或运行时内存检查，这是本地设备密钥模型的已知边界。

管理员在 MoDi Monitor 中使用 Android Keystore 签名批准、拒绝或撤销。服务端 SQLite 保存公钥、设备状态、访问申请、通知事件和审计记录。Approved 长期有效，直到管理员撤销；服务端的 AuthorizedKeysCommand 仅在认证时返回获批公钥。撤销会阻止新 SSH 认证，Downloader 在可访问控制 API 时检测到撤销后暂停任务并关闭现有本地隧道；如果客户端离线，已建立的 SSH 连接要等连接关闭或服务端终止才消失。

## 私人版

只有显式设置 MoDiPrivateBuild=true 且构建时提供本机身份材料时，才启用 PrivateIdentityProvider。该私有产物包含可提取的加密 SSH 身份材料，只供本人使用，严禁作为共享 Release 发布。私人版不改变 HTTP 下载器的隧道强制策略。

## 故障与降级

- API、SQLite、签名、SSH 主机 pin 或 SSH 隧道失败时，状态明确失败；下载器不创建直连 HttpClient。
- 断线时现有分片调度和续传逻辑保持不变，只有已批准身份可以重连。
- 本机身份文件损坏或 DPAPI 无法解密时失败关闭；不会静默生成新 ID 或覆盖旧身份。
- 清除本机身份只删除本机 DPAPI 文件，不会撤销服务器上的长期授权记录；服务端撤销必须由 Monitor 管理员签名操作完成。
