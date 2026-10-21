<div align="center">

<img src="https://raw.githubusercontent.com/LaoYinBai/MoDi-Downloader/v1.0.0/src/SshSpeedDownloader.Desktop/Assets/modi-downloader.png" width="112" height="112" alt="MoDi Downloader：桥与下载箭头" />

# MoDi Downloader

### 墨堤 · 下载

**把链接交给云端出口，把文件留在自己电脑。**

[![正式版本](https://img.shields.io/github/v/release/LaoYinBai/MoDi-Downloader?label=正式版&color=47937F&style=for-the-badge)](https://github.com/LaoYinBai/MoDi-Downloader/releases/latest)
![Windows x64](https://img.shields.io/badge/Windows-x64-86BFD8?style=for-the-badge&logo=windows&logoColor=242A2D)
![使用方式](https://img.shields.io/badge/使用方式-管理员审批-E8863C?style=for-the-badge)

[**立即下载安装版**](https://github.com/LaoYinBai/MoDi-Downloader/releases/download/v1.0.0/MoDiDownloader-1.0.0-win-x64-setup.exe) · [查看最新版本](https://github.com/LaoYinBai/MoDi-Downloader/releases/latest) · [使用教程](#三步开始下载) · [遇到问题](#常见问题)

</div>

---

> [!IMPORTANT]
> **程序可以公开下载，但云端节点需要管理员批准后才能使用。**
> 第一次打开，点击「申请使用下载器」，等待管理员在手机上批准即可。你不需要填写服务器地址、配置 SSH，也不需要向任何人提供私钥或口令。

## 这是做什么的？

MoDi Downloader 是一款 Windows 桌面下载器。它通过项目提供的云端节点访问下载地址，文件直接保存在你的电脑上，**不会先把整个文件下载到服务器再传给你**。

你只需要做三件事：

<div align="center">

**下载安装 → 申请并获得批准 → 粘贴链接下载**

</div>

| 下载体验 | 日常使用 |
| :--- | :--- |
| **动态分片**：把支持的文件拆成小块，让空闲连接继续领取任务 | **开箱即用**：不用安装 .NET、OpenSSH 或配置命令行环境 |
| **暂停与续传**：支持暂停、退出后重新打开继续 | **文件在本机**：默认保存到 Windows 的「下载」文件夹 |
| **自动重连**：连接中断后尝试恢复，不偷偷改走本地直连 | **完成反馈**：短提示音、音量调节、试听和 Windows 完成通知 |
| **自动寻优**：默认从 8 连接起步，按实际表现调整 | **浅色宣纸界面**：任务进度、速度和操作集中展示 |

> [!NOTE]
> 它不是全局 VPN，不会接管浏览器或其他软件的网络。文件下载请求强制通过下载器的 SSH 云端出口；设备申请和授权查询通过 HTTPS 控制接口完成。

## 三步开始下载

### 第一步：下载并打开

前往 [最新 Release 页面](https://github.com/LaoYinBai/MoDi-Downloader/releases/latest)，展开页面底部的 **Assets**，选择需要的文件。

| 你看到的文件 | 是什么 | 怎么选 |
| :--- | :--- | :--- |
| `MoDiDownloader-1.0.0-win-x64-setup.exe` | **安装版，推荐** | 双击安装，安装后可以通过桌面或开始菜单快捷方式打开 |
| `MoDiDownloader.exe` | **免安装版** | 放到一个方便找到的文件夹，直接双击运行 |
| `SHA256SUMS.txt` | 文件校验信息 | 用于核对下载文件，普通用户通常不需要打开 |
| `Source code (zip / tar.gz)` | 开发用源码 | **不是安装包**，想直接使用请不要选这个 |

以上以正式版 **v1.0.0** 为例；后续版本的安装包文件名会随版本号变化。

**运行要求：Windows x64。当前已在 Windows 11 验证，Windows 10 尚未独立验收。** 本期没有 Android、macOS 或 Linux 客户端。

> [!TIP]
> 不知道选哪个，就下载文件名带 **`setup.exe`** 的安装版。无需另装运行环境，也无需自己准备服务器或 SSH 密钥。

### 第二步：申请使用，等待批准

1. 打开 MoDi Downloader。
2. 在左侧云端区域点击 **「申请使用下载器」**。
3. 等待管理员在手机 MoDi Monitor 收到通知并批准。
4. 批准后，下载器会自动建立连接；看到 **「云端已连接」** 就可以开始下载。

授权状态通常每 **15 秒**检查一次，也可以点击 **「刷新状态」**。

| 当前状态 | 你需要做什么 |
| :--- | :--- |
| 尚未申请 | 点击「申请使用下载器」 |
| 申请待批准 | 等待管理员处理，不用反复提交 |
| 已获批准 | 等待自动连接；连接异常时可点「重连」 |
| 申请被拒绝或已过期 | 按界面提示重新申请，或联系管理员 |
| 授权已撤销 | 联系管理员；不是重装程序就能恢复的 |

**批准后长期有效，直到管理员撤销。** 平时关闭再打开，不需要重新申请。

<details>
<summary><strong>给管理员：手机没有收到申请怎么办？</strong></summary>

确认手机 Monitor 已启用后台监控、已授予系统通知权限，并且管理员身份已在云端登记。审批通知依赖 Monitor 正常运行及网络连接，不是电脑点击申请后一定瞬间弹出。

普通使用者不需要安装 Monitor，也不需要自己搭建审批服务。

</details>

### 第三步：粘贴链接，加入队列

1. 复制文件的 **HTTP 或 HTTPS 下载链接**。
2. 粘贴到右侧的下载链接输入框。
3. 检查保存目录。想为这一个任务换位置，点击 **「本任务目录…」**。
4. 保持默认 **8 连接**和 **「自动寻优 1–64」**即可。
5. 点击 **「加入队列」**，等待任务完成。

完成后，可以点击 **「打开文件」**，或点击 **「所在目录」**找到文件。

> [!IMPORTANT]
> **下载链接不等于网页地址。** 普通文章页、视频播放页、网盘分享页通常不能直接作为文件下载。当前不提供磁力、BT、网页解析或登录 Cookie 导入功能；需要登录的链接不保证可用。

## 日常操作，一眼看懂

| 按钮 / 信息 | 用途 |
| :--- | :--- |
| **暂停** | 暂时停止，保留续传进度。只是想晚点再下，选这个 |
| **继续** | 从保留的任务继续；下载器会先检查源文件是否仍然一致 |
| **重试** | 失败后重新开始尝试，**可能从头下载**，不要当成「继续」 |
| **取消** | 结束任务，并清理该任务的未完成临时文件；不要用它代替暂停 |
| **任务详情** | 展开查看来源、保存路径、分片进度、重试次数和最近错误 |
| **重连** | 重新尝试连接云端，不会跳过审批或主机校验 |
| **MiB/s** | 当前下载速度，数值越大表示传输越快；它不是运营商常说的 Mbps |
| **总大小未知** | 源站未提供可靠文件长度，不一定代表下载失败 |

### 想退出，明天接着下？

建议先点击 **「暂停」**，再正常关闭程序。重新打开、连接成功后，在原任务上点击 **「继续」**。

请保留任务的临时文件和下载器的应用数据。续传需要源站支持相应能力；如果文件内容、下载链接有效期或校验标识发生变化，下载器会停止不安全的拼接，可能需要重新下载。

### 文件到底存在哪里？

默认是 Windows 文件资源管理器里的 **「下载」**文件夹，包括你自己修改过位置的系统下载目录。

- **只改一个任务**：添加前点击「本任务目录…」。
- **以后都存到另一个位置**：展开左侧「默认下载目录」，点击「更改默认…」。
- **改回系统目录**：点击「恢复系统下载」。

更改默认目录**不会搬动已有任务的文件**，也不会改写它们的续传路径。目录无法访问或不可写时会提示错误，不会偷偷存到别处。

### 完成提示音在哪里调？

展开左侧 **「下载完成反馈」**，可以开关声音、调节音量并点击「试听」。设置会自动保存。

只有任务真正完成并保存到最终位置后，才会触发成功反馈。暂停、失败和重试不会播放成功音；重复完成事件会被抑制，短时间多任务完成也不会连续叠加提示音。系统通知是否显示，还取决于 Windows 的通知设置。

## 常见问题

<details>
<summary><strong>下载器公开了，为什么还要等批准？</strong></summary>

公开的是程序和源码，不是无限制开放的云端带宽。只有管理员批准的设备才能使用项目提供的下载节点。

</details>

<details>
<summary><strong>一直显示未连接 / 正在重连怎么办？</strong></summary>

先确认本机网络正常、设备已获批准，再点击「重连」。仍然失败时展开「高级信息」，记录错误现象并联系管理员。

云端或网络临时不可用时，下载器会重试或显示原因，**不会静默改成本地直连**。不需要反复重装，也不要为了连接问题自行关闭 TLS 或主机密钥校验。

</details>

<details>
<summary><strong>为什么某个国外链接还是下载不了？</strong></summary>

走云端出口不代表所有站点都能访问。源站可能限制云服务器 IP、要求登录、使链接过期，或本身连接不稳定。

请先确认拿到的是有效的文件直链，查看任务详情里的错误，再尝试其他合法可用的下载来源。下载器不会因此修改你的系统代理或服务器的全局代理设置。

</details>

<details>
<summary><strong>连接数开到 64，为什么反而更慢？</strong></summary>

连接越多不一定越快，还会受到本机网络、云端带宽、SSH 隧道和源站限制。建议保持默认 8 连接并开启自动寻优，不需要一开始就拉满。

不支持分片的源站会自动使用单连接。当前每任务的手动并发目标在添加任务时选择，运行中可由自动策略调整。

</details>

<details>
<summary><strong>换电脑、重装或使用免安装版，需要重新申请吗？</strong></summary>

同一 Windows 用户下正常升级或重新安装，保留原有应用数据时，可以继续使用原设备身份。

**换电脑、换 Windows 用户，或删除设备身份数据后，需要重新申请。** 免安装只是不用运行安装向导，不代表授权和设置会跟着 U 盘一起迁移。不要把自己的设备身份文件发给别人。

</details>

<details>
<summary><strong>Windows 提示未知发布者 / SmartScreen 怎么办？</strong></summary>

当前正式版未进行代码签名，因此 Windows 可能显示信誉提示。正式 Release 不等于已经获得 Windows 代码签名。

请只从本仓库的官方 Release 获取程序；不确定文件来源时不要运行。需要进一步核对，可使用 Release 内的 `SHA256SUMS.txt` 比较文件哈希。不要为此关闭系统安全防护。

</details>

<details>
<summary><strong>卸载会删除已经下载的文件吗？</strong></summary>

不会。卸载会移除程序及快捷方式，保留已下载文件、临时文件、任务记录和设备身份。

程序默认安装在 `%LOCALAPPDATA%\Programs\MoDiDownloader`，设置与任务记录位于 `%LOCALAPPDATA%\MoDiDownloader`。手动清理应用数据可能导致续传记录丢失或需要重新申请授权。

</details>

## 连接与隐私

- **不索要管理员 SSH 私钥**：共享安装包不包含管理员私钥、口令或预生成的设备身份。
- **每台设备独立身份**：本机自动生成设备密钥，并使用 Windows 用户级保护保存；私钥不会通过普通申请 API 上传。
- **申请不是匿名的**：云端保存设备名称、公钥及审批状态，用于识别和管理已授权设备。管理员可以撤销授权。
- **文件保存在本机**：云服务器负责转发网络流量，不组装、缓存完整下载文件。
- **不等于匿名工具**：目标站点看到的是云端出口；本工具不承诺匿名性，也不保证任意站点可达。

请仅下载你有权获取的内容，合理使用共享节点带宽。

## 验证记录

**v1.0.0 已完成真实链路验证**：申请、手机通知与批准、云端保存授权、Windows 下载、暂停续传及 SSH 断线恢复。97 项客户端测试和 68 项 Ubuntu 服务端测试通过。

一次官方文件下载对比的平均速度如下，**仅用于说明这次测试结果，不是你的速度保证**：

| 连接数 | 1 | 4 | 8 | 16 |
| :--- | ---: | ---: | ---: | ---: |
| 平均速度 | 0.63 MiB/s | 1.45 MiB/s | 2.27 MiB/s | 2.42 MiB/s |

四份文件的 SHA-256 均与官方校验文件一致。当前还没有独立干净 Windows 虚拟机、长期运行和 32 / 64 连接的实测结论。

[查看完整验收记录](https://github.com/LaoYinBai/MoDi-Downloader/blob/v1.0.0/ACCEPTANCE_20261021.md)

<details>
<summary><strong>开发者入口：源码、构建与技术说明</strong></summary>

普通使用者不需要执行以下命令。想构建与正式版对应的程序，请使用对应 Release Tag，避免混用不同开发分支。

```powershell
git clone --branch v1.0.0 --depth 1 https://github.com/LaoYinBai/MoDi-Downloader.git
cd MoDi-Downloader
dotnet restore .\SshSpeedDownloader.sln
dotnet test .\SshSpeedDownloader.sln -c Release
.\tools\TestMoDiDownloaderSharedPublish.ps1
.\tools\BuildMoDiDownloaderSetup.ps1
```

构建需要 .NET 10 SDK；生成安装包还需要本机 Inno Setup。接收安装包的普通电脑不需要这些开发工具。

| 模块 | 职责 |
| :--- | :--- |
| `SshSpeedDownloader.Core` | 下载任务模型、分片规划、并发策略、文件及续传规则 |
| `SshSpeedDownloader.Transport` | 设备身份、授权 API、SSH.NET、SOCKS5 与 HTTP 下载 |
| `SshSpeedDownloader.Desktop` | Avalonia 界面、Windows 设置、目录选择与完成反馈 |
| `SshSpeedDownloader.Tests` | 调度、文件完整性、身份、代理和异常场景测试 |

共享发行包通过 `MoDiPrivateBuild=false` 构建。打包脚本会检查 Shared 标记、私人身份资源缺失、提示音资源存在，以及发布目录中只有一个可执行文件。历史私人构建模式仅供本机开发，**不得用于公开发包**。

资源边界：最多 4 个活跃任务、64 条全局 HTTP 连接、2 条 SSH 隧道；默认 1 MiB 动态任务块、64 KiB I/O 缓冲区，每个请求或分片最多尝试 5 次。不设置带宽限速，但不会用无限并发或无限重试代替可靠性。

撤销会阻止新的 SSH 认证；正常客户端每 15 秒检查并关闭被撤销的连接。对改造过的已连接客户端，移除公钥并不等于强制断开，仍需服务端终止会话。

- [身份与授权架构](https://github.com/LaoYinBai/MoDi-Downloader/blob/v1.0.0/AUTH_ARCHITECTURE.md)
- [测试、性能与已知限制](https://github.com/LaoYinBai/MoDi-Downloader/blob/v1.0.0/ACCEPTANCE_20261021.md)
- [音效来源及第三方说明](https://github.com/LaoYinBai/MoDi-Downloader/blob/v1.0.0/THIRD_PARTY_NOTICES.md)

</details>

---

<div align="center">

界面参考 [PCL2](https://github.com/Meloong-Git/PCL) 的任务信息层级与展开交互，使用 Avalonia 独立实现。<br />
未复制其代码、图标或美术资源；完成音来自 [Kenney Interface Sounds](https://kenney.nl/assets/interface-sounds)，采用 CC0 授权。

**墨堤 · 下载｜云端转发，本机落盘。**

</div>
