# AI Signal Guard Pages 版本架构设计

## 目标

将当前线上首页永久归档为 `/v1/`，将新版发布为 `/v2/`，并让根地址 `/` 始终直接显示最新正式版。所有页面的 canonical、Open Graph 与复制报告统一使用 `https://betaer.github.io/AiSignalGuard/`。

## 文件与访问路径

```text
index.html       最新正式版，当前对应 v2
v1/index.html    v1 永久归档
v2/index.html    v2 永久归档
assets/          共用静态资源
```

不保留 `index-v1.0.html` 或 `index-v2.0.html`，避免与版本目录形成重复归档。版本目录页面使用 `../` 访问根目录共用资源，页面内锚点继续留在当前版本。

## 页面规则

- 根 `index.html` 与 `v2/index.html` 使用同一份 v2 功能代码；根入口不跳转，地址栏保持唯一公开地址。
- `v1/index.html` 固定保存实施前的根首页，不随新版继续变化。
- v2 清除 `ip.cx`、`ipcx`、`本站` 相关标记与文案，内部版本属性统一为通用 `data-version`。
- `/v1/` 与 `/v2/` 可以直接访问，但页面分享、复制报告与 SEO canonical 均指向根地址。

## Git 版本规则

- `main` 始终保存最新正式站点与历史版本目录。
- 用 annotated tag `v1.0.0` 标记切换前的旧首页提交，用 `v2.0.0` 标记新版发布提交。
- 每个 tag 建立 GitHub Release，使用中文发布说明；GitHub 自动生成源码 ZIP/TAR，不使用 GitHub Packages。
- 不维护长期 v1/v2 分支，避免修复在多个分支间漂移。

## 验证

- 静态检查三个入口、资源路径、版本标记、canonical 和分享地址。
- 在本地 HTTP 服务器分别打开 `/`、`/v1/`、`/v2/`，确认没有资源 404 和运行时错误。
- 运行现有 IPCX 证据与语义回归测试，确保旧页面与新版能力未被目录迁移破坏。
- 发布前确认 Git 状态、tag 指向与 Release 资产。
