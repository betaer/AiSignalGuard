# AI Signal Guard 固定 999+ Star 徽标设计

## 目标

最新版根入口与 `/v2/` 的 GitHub 操作固定显示 `999+`，不再读取仓库真实 Star 数。显示值从首帧开始稳定，不出现 `Star`、真实数字或加载后的跳变；`/v1/` 继续作为不可变历史归档。

## 方案选择

- 不采用“真实计数达到 1000 后才封顶”：当前仍会显示较小真实值。
- 不采用“真实计数设置 999+ 下限”：仍会产生无意义网络请求和缓存状态。
- 采用固定 `999+`：删除真实计数数据流，只保留 GitHub 仓库链接和 Star 引导。

## 页面与交互

- `#star-count` 首帧文本固定为 `999+`。
- `#github-label` 首帧文本固定为 `GitHub · 999+`。
- `#github-shortcut` 使用 `data-star-state="fixed"`，无加载态和失败态。
- 链接仍打开 `https://github.com/betaer/AiSignalGuard`，现有图标、布局、触控区域和 Star 引导弹窗保持不变。
- 辅助名称明确包含 `999+ Star`，与可见文本一致。

## 数据流

删除最新版中的 Star 数归一化、LocalStorage 缓存、缓存有效期和 GitHub Repository API 请求。页面初始化不再执行 `loadStars()`，因此 Star 徽标不会额外产生网络请求。

## 版本边界

- 同步修改根 `index.html` 与 `v2/index.html`，保持两个 v2 入口能力一致。
- 不修改 `v1/index.html`、旧 IPCX、IPCX Remix 或旧控制器文件。

## 验证

- 静态契约检查根页和 v2 均包含固定 `999+`，并且不包含 GitHub Repository API、Star 缓存键或 `loadStars()`。
- 版本契约继续验证根页与 `/v2/` 只存在相对路径差异。
- 浏览器检查首帧可见文字、辅助名称、链接和无额外 GitHub API 请求。
- 执行仓库发布级测试，推送后确认 GitHub Pages 根入口和 `/v2/` 已显示固定值。
