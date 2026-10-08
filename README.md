# my-homepage

b1000mk 的个人主页与开源作品集，基于 **Astro 5** 构建的极简编辑排版风单页。

石墨深色主题、超大标题排版与编号分节结构，无任何客户端框架。

---

## ✨ 特性亮点

- ⚡ **Astro 5 核心驱动**：全静态生成（SSG），零客户端框架，秒级首屏加载。
- 🖋 **极简编辑排版**：128px 超大标题 + 编号分节（01 项目 / 02 工具 / 03 理念 / 04 联系），专注内容本身。
- 🌑 **石墨深色主题**：固定深色配色（石墨 `#18181B` + 亮蓝 `#60A5FA` 点缀），Space Grotesk 与 DM Sans 双字体组合。
- 📱 **全终端响应式**：针对移动端、平板与桌面端精细调校的排版与交互体验。
- 🔍 **SEO 与元数据优化**：完备的 OpenGraph、Twitter 卡片与语义化 HTML5 标签。
- 📋 **交互微细节**：一键复制主页链接（约 40 行原生 JS，带成功状态反馈）。

---

## 🛠️ 本地开发

```bash
# 安装依赖
npm install

# 启动本地开发服务 (默认 http://localhost:4321)
npm run dev

# 构建生产版本 (输出到 dist/)
npm run build

# 本地预览生产构建产物
npm run preview
```

---

## 🚀 Cloudflare Pages 部署配置

项目通过 Git 集成托管于 Cloudflare Pages，推送到 `main` 分支后自动触发构建。

在 Cloudflare Pages 控制台设置如下：

| 配置项 | 推荐值 |
| :--- | :--- |
| **Framework preset（框架预设）** | `Astro` |
| **Build command（构建命令）** | `npm run build` |
| **Build output directory（输出目录）** | `dist` |
| **Environment variable（环境变量）** | `NODE_VERSION` = `22` |

---

## 📁 目录结构

```text
├── public/                 # 静态资源 (favicon 等)
├── src/
│   ├── layouts/
│   │   └── Layout.astro          # 基础 HTML 布局、SEO 元数据与字体加载
│   ├── styles/
│   │   └── global.css            # 设计系统：色彩变量、排版与响应式
│   └── pages/
│       └── index.astro           # 主页入口：全部内容与复制链接微交互
├── astro.config.mjs        # Astro 配置文件
├── package.json            # 依赖与脚本
├── tsconfig.json           # TypeScript 配置
└── wrangler.toml           # Cloudflare Pages 构建输出配置
```
