# Floating X Shortcut Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在新版根入口和 `/v2/` 的统一浮动工具栏中增加响应式 Betaer X 主页入口。

**Architecture:** 复用单文件页面现有的 `.floating-tool-button` 组件，以内联 SVG 提供 X 图标，不增加脚本状态或外部图片请求。桌面端默认只显示图标，并复用统一的悬停/聚焦规则显示“作者 X @Betaer”；移动端复用现有断点隐藏提示，并在窄屏断点保持七项工具不溢出。

**Tech Stack:** HTML、CSS、内联 SVG、Node.js 内置测试、Playwright 浏览器验收。

---

### Task 1: 增加失败的版本契约测试

**Files:**
- Modify: `tests/versioned-pages.test.mjs`

- [ ] **Step 1: 为根入口和 `/v2/` 断言 X 入口、链接安全属性、GitHub 后置顺序、默认无常驻标签以及“作者 X @Betaer”悬停文案。**
- [ ] **Step 2: 运行 `npm run test:versions`，确认新断言因旧版仍常驻显示重复“X”而失败。**

### Task 2: 实现 X 入口和响应式布局

**Files:**
- Modify: `index.html`
- Modify: `v2/index.html`

- [ ] **Step 1: 在两份新版页面的 GitHub 按钮之后加入 `#x-shortcut`，链接到 `https://x.com/intent/user?screen_name=betaer` 并设置 `target="_blank" rel="noopener noreferrer"`。**
- [ ] **Step 2: 保留 `.floating-x-icon`，删除 X 标签的强制常驻样式，并把统一悬停文案改为“作者 X @Betaer”。**
- [ ] **Step 3: 在移动端隐藏悬停文案，并保留 `360px` 窄屏七项按钮布局。**

### Task 3: 验证与发布

**Files:**
- Verify: `index.html`
- Verify: `v2/index.html`
- Verify: `tests/versioned-pages.test.mjs`

- [ ] **Step 1: 运行 `npm run test:versions`、`npm run check:full` 和 `git diff --check`。**
- [ ] **Step 2: 用浏览器核对桌面与移动端计算样式、链接、新窗口属性及工具栏边界。**
- [ ] **Step 3: 提交并推送到 `origin/main`，等待 GitHub Pages 完成后验证线上根入口。**
