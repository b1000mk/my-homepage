# my-homepage

b1000mk 的现代极简个人主页与作品集，基于 **Astro 5** 重构构建。

结合 Apple 与 Linear 极简科技美学，具备原生深/浅色模式切换、流光环境光效、交互聚光灯卡片与毫秒级全静态极速交付。

---

## ✨ 特性亮点

- ⚡ **Astro 5 核心驱动**：全静态生成（SSG），零客户端运行时多余开销，秒级首屏加载。
- 🌓 **深浅双色主题**：内置无闪烁（Anti-FOUC）主题切换器，支持记住用户偏好与系统偏好自动同步。
- 🎨 **高级视觉质感**：动态 Ambient 流光微动效、点阵背景纹理、高斯毛玻璃面板（Glassmorphism）与卡片鼠标光斑跟随。
- 📱 **全终端响应式**：针对移动端、平板与桌面端精细调校的排版与交互体验。
- 🔍 **SEO 与元数据优化**：完备的 OpenGraph、Twitter 卡片与语义化 HTML5 标签。
- 📋 **交互微细节**：一键复制主页与联系方式 Toast 气泡提醒、平滑返回顶部。

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
├── public/                 # 静态静态资源 (favicon, 图标等)
├── src/
│   ├── components/         # 模块化 Astro 组件
│   │   ├── AboutSection.astro    # 哲学与简介
│   │   ├── ContactSection.astro  # 联系与社交卡片
│   │   ├── Footer.astro          # 页脚与返回顶部
│   │   ├── Hero.astro            # 头部 Hero 区域与头像
│   │   ├── ProjectCard.astro     # 聚光灯开源项目卡片
│   │   ├── TechStack.astro       # 技术与工具栈徽章
│   │   └── ThemeToggle.astro     # 深浅色模式切换器
│   ├── layouts/
│   │   └── Layout.astro          # 基础 HTML 布局与全局交互逻辑
│   ├── styles/
│   │   └── global.css            # 现代设计系统、色彩变量与动效
│   └── pages/
│       └── index.astro           # 主页入口页面
├── astro.config.mjs        # Astro 配置文件
├── package.json            # 依赖与脚本
└── tsconfig.json           # TypeScript 配置
```
