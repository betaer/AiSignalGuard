# IPCX Remix v1.3.0 结果中心与工具明细设计

## 目标

修复 v1.2.0 的信息架构缺陷：用户进入页面即可看到本轮 19 项真实检测结果；进入七个高级工具后，必须看到逐项结果或逐项能力状态，而不是只有一段未启用说明。

## 范围与约束

- 继续使用纯静态单页、Hash 路由、浏览器内 state；不新增数据库或自有服务器。
- 保留 index-ipcx-remix-v1.2.0.html 与 ipcx-remix-v1.2.0.js 作为回滚版本。
- 新版本为 index-ipcx-remix-v1.3.0.html 与 ipcx-remix-v1.3.0.js。
- 不复制现有 signal-row 或 data-row-id；首页镜像与工具列表均从同一 state 派生。
- 成功、警告、失败、跳过和需要服务器的终态都必须保留；缺失证据不得转成绿色结论。

## 用户可见结构

### 首页 #/overview

顺序固定为：结论卡 → 19 项紧凑结果索引 → 四个结果域入口 → 隐私边界。结果索引分为出口 IP 6 项、身份信号 4 项、网络泄漏 4 项、多源互证 5 项。每行包含名称、当前值或状态、证据覆盖摘要与进入对应结果域的 Hash 链接；首个结果行在无需滚动一个完整桌面视口的位置可见。

### 既有结果域

保留网络、泄漏、路径、浏览器四个完整证据域。规范的 19 个 signal-row 只有一份，由同一个 state 更新；首页只使用 data-core-result-ref 镜像，不制造重复 ID。

### 七个工具

| 工具 | 真实列表 | 未接入或服务器项 |
|---|---|---|
| IP | 公网出口 + 10 家 IP 情报来源 | 可继续扩展的来源列为 skipped |
| DNS | bash.ws 本轮解析器记录与探针终态 | 多生态解析器逐项列为 skipped |
| STUN | 10 个节点的候选地址、地址族、耗时与终态 | 22 节点扩容逐项列为 skipped |
| CDN | 浏览器可观察的目标和字段清单 | 需要 CORS 或响应头权限的目标为 skipped |
| Split | 现有 HTTP、STUN、IP 情报路径基线 | 40 个目标按项列为 skipped |
| Multi | 10 IP + 10 Route + 10 STUN 的 30 源联合矩阵 | 1,648 远端节点逐项标记 requires-server |
| Latency | ipify、IP、Route、STUN 已有 latencyMs | 重复采样和抖动矩阵按项标记 skipped |

工具列表项必须显示真实名称、状态、证据或不能取得的具体原因。服务器依赖行必须明确需要服务器，但不提供虚假的开始按钮或成功数字。

## 数据流与组件边界

控制器新增以下边界：

- buildCoreResultModels(state)：将 19 条核心行转为首页镜像模型。
- buildToolProbeModels(tool, state)：按工具读取既有 state，返回真实、跳过、服务器依赖的列表模型。
- renderOverviewResultIndex(models)：只更新首页镜像容器。
- renderToolResultLists(state)：只更新七个工具列表容器。
- renderProbeList(container, models)：统一渲染 data-probe-* 结构与终态样式。

已有 render 先更新证据行，再调用首页与工具列表渲染；路由切换只控制显隐，不触发新的重复网络请求。IP、DNS、STUN、Route 和延迟工具不各自启动探测。

## 错误与隐私

- 网络失败、CORS、超时、字段缺失分别展示，不把未取得写成安全。
- 复制摘要与 AI 报告继续复用隐私遮罩；工具列表中的 IP、ASN、组织、候选地址同样响应遮罩。
- 外部来源全部是用户当前浏览器直接请求；页面不保存结果到服务器。

## 测试验收

- 静态合同：v1.3.0 文件存在，首页 19 个 data-core-result-ref，七个工具各有非空 data-tool-result-list。
- 语义 E2E：夹具下 IP=10、DNS=动态记录数、STUN=10、Multi=30，其他工具包含逐项 skipped 或 requires-server 状态。
- 路由 E2E：overview 与七个工具 Hash 切换后，当前视图中列表可见且不读取隐藏视图数据。
- 六视口 E2E：首屏结果行、列表卡片、移动端横向导航和浮动工具栏无溢出或遮挡。
- npm run check:full 必须通过，覆盖率保持 80% 以上；旧入口与 v1.2.0 回归不受影响。
