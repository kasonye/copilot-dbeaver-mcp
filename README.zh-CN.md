# DB-Guard MCP

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![Java 17+](https://img.shields.io/badge/JDK-17%2B-ED8B00.svg)](https://adoptium.net/)
[![MCP Compatible](https://img.shields.io/badge/MCP-2025--03--26-green.svg)](https://modelcontextprotocol.io/)

**[English README](./README.md)** | **[安全架构说明 (SECURITY.md)](./SECURITY.md)**

**DB-Guard MCP** 是一个**零密码配置、纵深防御**的 **Model Context Protocol (MCP)** 服务端，用于在 **Windows、macOS、Linux** 上将 **GitHub Copilot**（IntelliJ IDEA / VS Code）、**Cursor**、**Claude Code** 等 AI 编程助手与本机 **DBeaver** 已保存的数据库连接安全打通（支持 MariaDB、MySQL、Oracle、PostgreSQL、GaussDB、H2 等）。

专为解决日常研发中的高频痛点而生：**当出现脏数据或与数据库相关的日志报错时，让 AI 在同一上下文里自动串联「应用日志堆栈 + 业务源码约束 + 实时脱敏查库」，在回滚事务中安全预演修复方案，并在强制完成原始数据冷备与变更台账留痕后完成修复。**

---

## 核心特性

1. **零密码直接复用 DBeaver 连接（含 SSH 隧道）**
   跨平台自动扫描 DBeaver 工作区（`workspace6`）、本地已下载的 JDBC 驱动缓存及 SSH 隧道插件（SSHJ）。数据库凭据**仅在本地 JVM 进程内存中解密直连**，绝不写入配置文件、绝不打印日志、绝不回传给云端大模型。
2. **协议与引擎层双重只读硬锁**
   所有诊断查询（`diagnose_query` / `inspect_schema` / `explain_query`）自动覆写 `allowMultiQueries=false` 阻断多语句注入，并在会话层强制下发 `Connection.setReadOnly(true)` + `SET SESSION TRANSACTION READ ONLY`（Oracle 为 `SET TRANSACTION READ ONLY`），配合超时中断、行数上限及结束强制 `ROLLBACK`——即便 DBeaver 保存的是管理员账号，数据库引擎本身也会拒绝任何写操作。
3. **保留脏数据特征的动态隐私脱敏 (PII Masking)**
   返回给云端大模型前自动掩码证件号、姓名、手机、邮箱、密码/Token 等敏感列与敏感值，同时精准保留 **`NULL` 与空串 `""` 区别、字符总长度、首尾异常空格数**（例如 `J***h [MASKED:PII len=12 trail_ws=2]`），兼顾数据隐私合规与脏数据排障精度。
4. **真事务回滚式预演 (`preview_remediation`)**
   在真实库开启事务执行 `START TRANSACTION` $\rightarrow$ 修改前查询 $\rightarrow$ 目标 DML $\rightarrow$ 修改后查询 $\rightarrow$ **底层强制 `ROLLBACK`**，零落库验证外键/触发器约束并展示精确前后对比。
5. **「无备份、不修改」强制冷备与双格式变更审计台账**
   无论是唤起 DBeaver 人工审阅提交（`open_remediation_in_dbeaver`），还是在允许的开发库直接提交（`apply_remediation`），执行前**必须先成功落盘校验三份备份文件**（未脱敏原始行 `backup_record.json`、`before_rows_insert.sql` 冷备、按真实主键生成的逆向可执行 `rollback.sql`），并追加记录至 `~/.db-guard-mcp/change-logs/modification_audit.md` 与 `.jsonl`。

---

## 环境要求

- **Python** `3.10+`
- **JDK** `17+`（确保 `java` 与 `javac` 在系统 `PATH` 中）
- **DBeaver**（社区版或专业版均可，连接已勾选“保存密码”并已下载对应驱动）

---

## 快速开始

### 1. 安装与环境自检

```bash
git clone https://github.com/kasonye/copilot-dbeaver-mcp.git
cd copilot-dbeaver-mcp
pip install -e .

# 运行一键环境、驱动与 DBeaver 连接探测自检
db-guard-mcp --doctor
```

### 2. 配置到 GitHub Copilot（全局一次配置，所有项目通用）

- **IntelliJ IDEA / JetBrains 系列**：
  - Windows: `%LOCALAPPDATA%\github-copilot\intellij\mcp.json`
  - macOS / Linux: `~/.config/github-copilot/intellij/mcp.json`
- **VS Code**：打开命令面板执行 `MCP: Open User Configuration` 编辑全局 `mcp.json`

```json
{
  "servers": {
    "db-guard-dbeaver": {
      "type": "stdio",
      "command": "db-guard-mcp",
      "args": []
    }
  }
}
```

打开 **GitHub Copilot Chat** 切换至 **Agent** 模式，直接用自然语言指定 DBeaver 中的连接名与库名即可：
> - *“扫描当前项目日志里的报错，结合 Entity 代码去 `localhost` 的业务库查一下哪条脏数据导致的，并预演修复。”*
> - *“用 DBeaver 里的测试库连接查一下订单 `ORD-xxx` 的异常状态，预演无误后在 DBeaver 打开修复脚本给我确认提交。”*
> - *“查看最近做过的数据修改审计日志，并把上次修改用备份回滚。”*

---

## 自定义安全策略（可选，支持热加载）

可将 [`config.example.yaml`](./config.example.yaml) 复制到 `~/.db-guard-mcp/config.yaml`（或项目目录下的 `config.local.yaml`），随时调整查询超时、单次最大修改行数（`max_write_rows`，默认 `20`）以及允许直接提交的连接白名单（`allow_direct_apply_connections`，默认仅放行 `localhost` / `127.0.0.1`）。修改后无需重启 IDE 即时生效。

---

## 运行测试套件

```bash
python -m unittest discover -s tests -v
```

---

## 开源协议

本项目基于 [MIT License](./LICENSE) 开源发布。
