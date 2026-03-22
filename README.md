# 敏感信息检查工具 (Sensitive Info Check)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

一款用于检查代码中是否存在敏感日志打印的安全工具，帮助开发者在代码提交前发现潜在的安全风险。

## 目录

- [项目概述](#项目概述)
- [功能特性](#功能特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [命令行参数](#命令行参数)
- [支持的敏感信息类型](#支持的敏感信息类型)
- [支持的编程语言](#支持的编程语言)
- [核心模块说明](#核心模块说明)
- [配置与自定义](#配置与自定义)
- [示例与使用场景](#示例与使用场景)
- [测试说明](#测试说明)
- [项目结构](#项目结构)
- [贡献指南](#贡献指南)
- [许可证](#许可证)

## 项目概述

在日常开发中，开发者可能会无意中在日志中打印敏感信息，如密码、API密钥、身份证号等。这些敏感信息一旦进入日志系统，可能被未授权人员访问，造成严重的安全隐患。

**敏感信息检查工具 (SIC)** 旨在帮助开发者：

- 在代码提交前自动检测敏感日志打印
- 支持 42 种常见敏感信息模式
- 支持 16 种主流编程语言
- 提供详细的修复建议
- 支持导出Excel格式的安全报告
- 可集成到 CI/CD 流程中

## 功能特性

- **多语言支持**: 支持 Python、JavaScript、Java、Go 等 16 种编程语言
- **丰富的检测模式**: 内置 42 种敏感信息检测规则
- **灵活的扫描方式**: 支持文件扫描、目录扫描、全代码扫描
- **多种输出格式**: 支持终端彩色输出、JSON 格式输出和 Excel 报告导出
- **Excel报告**: 生成包含汇总统计和详细问题的Excel报告
- **严重级别分类**: 按风险等级分类（CRITICAL/HIGH/MEDIUM/LOW）
- **修复建议**: 为每个检测项提供安全建议
- **可扩展**: 支持自定义检测规则

## 安装

### 系统要求

- Python 3.8+
- pip 包管理器

### 从源码安装

```bash
# 克隆仓库
git clone https://github.com/RebornL/sensitive-info-check.git
cd sensitive-info-check

# 安装依赖
pip install -e .
```

### 依赖说明

| 依赖包 | 版本要求 | 用途 |
|--------|----------|------|
| click | >=8.0.0 | 命令行框架 |
| colorama | >=0.4.0 | 终端彩色输出 |
| pyyaml | >=6.0 | YAML配置解析 |
| toml | >=0.10.0 | TOML配置解析 |
| openpyxl | >=3.0.0 | Excel报告生成 |

## 快速开始

### 基本使用

```bash
# 扫描单个文件
sic scan ./src/main.py

# 扫描整个目录
sic scan ./src

# 显示代码上下文
sic scan ./src --show-context

# JSON 格式输出
sic scan ./src --json
```

### 查看帮助

```bash
# 查看所有命令
sic --help

# 查看扫描命令帮助
sic scan --help

# 列出支持的敏感信息模式
sic list-patterns

# 列出支持的编程语言
sic list-languages
```

## 命令行参数

### `sic scan` - 扫描文件或目录

| 参数 | 简写 | 说明 |
|------|------|------|
| `path` | - | 要扫描的文件或目录路径 |
| `--recursive` | `-r` | 递归扫描目录（默认启用） |
| `--all-code` | `-a` | 扫描所有代码，不仅是日志语句 |
| `--severity` | `-s` | 过滤严重级别 (critical,high,medium,low) |
| `--category` | `-c` | 过滤类别 (password,api_key,token等) |
| `--ignore-dir` | `-i` | 忽略的目录（可多次指定） |
| `--extension` | `-e` | 扫描的文件扩展名（可多次指定） |
| `--show-context` | - | 显示代码上下文 |
| `--json` | - | JSON 格式输出 |
| `--excel` | `-x` | 导出Excel报告到指定路径 |
| `--no-summary` | - | 不显示摘要 |
| `--quiet` | `-q` | 静默模式，只显示问题 |

### 使用示例

```bash
# 只检测高危级别问题
sic scan ./src -s critical,high

# 只检测密码相关
sic scan ./src -c password,api_key

# 忽略特定目录
sic scan ./src -i tests -i migrations

# 只扫描特定文件类型
sic scan ./src -e .py -e .js

# 扫描所有代码（包括非日志语句）
sic scan ./src -a

# 静默模式，适合CI/CD
sic scan ./src -q --json

# 导出Excel报告
sic scan ./src -x report.xlsx

# 导出Excel报告到指定路径
sic scan ./src --excel /path/to/report.xlsx
```

### 退出码

| 退出码 | 说明 |
|--------|------|
| 0 | 未发现敏感信息问题 |
| 1 | 发现敏感信息问题 |

## 支持的敏感信息类型

### 按严重级别分类

#### CRITICAL（高危）

| 类型 | 说明 | 示例 |
|------|------|------|
| 密码变量 | password/passwd/pwd 赋值 | `password = 'secret123'` |
| API密钥 | api_key/apikey 变量 | `api_key = 'sk-xxx'` |
| 密钥 | secret_key/secret 变量 | `secret_key = 'xxx'` |
| 访问令牌 | access_token/auth_token | `token = 'ghp_xxx'` |
| 私钥 | RSA/ECDSA 私钥 | `-----BEGIN RSA PRIVATE KEY-----` |
| AWS密钥 | AWS Access Key | `AKIAIOSFODNN7EXAMPLE` |
| 带凭据URL | URL中包含用户名密码 | `mysql://user:pass@host/db` |
| 数据库连接串 | 包含凭据的连接串 | `jdbc:mysql://...` |

#### HIGH（高级）

| 类型 | 说明 | 示例 |
|------|------|------|
| 身份证号 | 中国18位身份证 | `11010519900307234X` |
| 银行卡号 | 16-19位银行卡号 | `6222021234567890123` |
| 护照号码 | 中国护照格式 | `DE1234567` |
| 港澳通行证 | 港澳通行证号 | `C12345678` |
| 台湾通行证 | 台湾通行证号 | `T12345678` |
| 驾驶证号 | 驾驶证编号 | `110105199003070512` |
| 社会保障号 | 社保号/SSN | `SSN: 123456789` |
| 医保卡号 | 医疗保险卡号 | `医保卡号：1234567890123456` |
| 军官证号 | 军官证件号 | `军字第123456号` |
| GPS位置轨迹 | 经纬度坐标 | `location: 39.9042, 116.4074` |
| 健康档案数据 | 病历号/住院号 | `病历号：BL12345678` |
| IMEI号 | 手机设备标识 | `imei: 359881060123456` |
| IMSI号 | 用户识别码 | `imsi: 460001234567890` |
| 心率数据 | 心率/心跳 | `heart_rate: 72bpm` |
| 血压数据 | 血压值 | `blood_pressure: 120/80mmHg` |
| 血糖数据 | 血糖值 | `blood_sugar: 5.6mmol/L` |
| 体重/BMI数据 | 体重或BMI | `weight: 65.5kg` |
| 步数数据 | 运动步数 | `step_count: 8500步` |
| 睡眠数据 | 睡眠时长 | `sleep_duration: 7.5小时` |
| 血型数据 | 血型信息 | `blood_type: A` |

#### MEDIUM（中级）

| 类型 | 说明 | 示例 |
|------|------|------|
| 手机号 | 中国11位手机号 | `13812345678` |
| 电子邮箱 | 邮箱地址 | `user@example.com` |
| 学籍号 | 学生学籍编号 | `学籍号：G123456789012` |
| 统一社会信用代码 | 企业信用代码 | `91110000600007336F` |
| 姓名 | 中文姓名赋值 | `user_name = '张三'` |
| 地址信息 | 详细地址 | `广东省深圳市南山区...` |
| 心率数据 | 心率/心跳 | `heart_rate: 72bpm` |
| 血压数据 | 血压值 | `blood_pressure: 120/80mmHg` |
| 血糖数据 | 血糖值 | `blood_sugar: 5.6mmol/L` |
| MAC地址 | 网卡物理地址 | `00:1A:2B:3C:4D:5E` |
| 设备序列号 | SN序列号 | `serial_number: C02XG0FDHV2Q` |
| 设备UUID | 设备唯一标识 | `device_uuid: 550e8400-...` |
| Android ID | 安卓设备ID | `android_id: 9774d56d682e549c` |
| IDFA/IDFV | iOS广告标识符 | `idfa: 4D6B9C3E-1A2B-...` |
| OAID | 匿名设备标识 | `oaid: 1a2b3c4d5e6f7a8b` |

#### LOW（低级）

| 类型 | 说明 | 示例 |
|------|------|------|
| IP地址 | IPv4地址 | `192.168.1.100` |

## 支持的编程语言

| 语言 | 支持的日志函数 |
|------|----------------|
| Python | `print`, `logging`, `logger`, `pprint` |
| JavaScript | `console.log/info/warn/error/debug` |
| TypeScript | `console.log/info/warn/error/debug` |
| Java | `System.out/err`, `Log4j`, `SLF4J`, `Android Log` |
| Kotlin | `println`, `print`, `Android Log` |
| Go | `fmt.Print/Printf/Println`, `log.Print/Printf` |
| Rust | `println!`, `print!`, `eprintln!`, `log::*!` |
| C | `printf`, `fprintf`, `sprintf`, `puts`, `syslog` |
| C++ | `std::cout/cerr/clog`, `printf` |
| C# | `Console.Write/WriteLine`, `Debug.Write`, `Serilog/NLog` |
| PHP | `echo`, `print`, `print_r`, `var_dump`, `error_log` |
| Ruby | `puts`, `print`, `p`, `logger.*`, `Rails.logger.*` |
| Swift | `print`, `debugPrint`, `dump`, `os_log.*` |
| Objective-C | `NSLog`, `printf` |
| Scala | `println`, `print`, `Log4j/SLF4J` |

## 核心模块说明

### `patterns.py` - 敏感信息模式定义

该模块定义了所有敏感信息的检测模式，是整个工具的核心。

```python
from sensitive_check.patterns import (
    SensitivePattern,    # 敏感信息模式类
    Severity,            # 严重级别枚举
    Category,            # 类别枚举
    SENSITIVE_PATTERNS,  # 预定义模式列表
    get_patterns_by_severity,    # 按级别获取模式
    get_patterns_by_category,    # 按类别获取模式
)
```

**主要功能**:

- 定义 `SensitivePattern` 数据类，包含模式名称、正则表达式、严重级别、描述、示例和修复建议
- 预定义 42 种敏感信息检测模式
- 提供按严重级别和类别筛选模式的函数

**示例**:

```python
# 获取所有高危模式
from sensitive_check.patterns import get_patterns_by_severity, Severity
critical_patterns = get_patterns_by_severity(Severity.CRITICAL)

# 获取密码相关模式
from sensitive_check.patterns import get_patterns_by_category, Category
password_patterns = get_patterns_by_category(Category.PASSWORD)
```

### `detector.py` - 日志检测引擎

该模块负责检测代码中的日志函数调用，支持多种编程语言。

```python
from sensitive_check.detector import (
    Language,                    # 编程语言枚举
    LogMatch,                    # 日志匹配结果
    detect_log_functions,        # 检测日志函数
    detect_log_functions_multi_language,  # 多语言检测
    get_supported_languages,     # 获取支持的语言
)
```

**主要功能**:

- 定义 `Language` 枚举，支持 16 种编程语言
- 定义 `LogFunction` 数据类，描述各语言的日志函数
- 提供 `detect_log_functions()` 函数检测代码中的日志调用
- 返回日志函数名、行号、列号等信息

**示例**:

```python
from sensitive_check.detector import detect_log_functions, Language

code = '''
print("Hello")
logging.info("User: " + username)
'''

matches = detect_log_functions(code, Language.PYTHON)
for match in matches:
    print(f"Line {match.line_number}: {match.function_name}")
```

### `scanner.py` - 代码扫描器

该模块整合模式和检测器，实现完整的代码扫描功能。

```python
from sensitive_check.scanner import (
    scan_file,          # 扫描单个文件
    scan_directory,     # 扫描目录
    FileScanResult,     # 文件扫描结果
    ScanResult,         # 总扫描结果
    LogSensitiveIssue,  # 敏感信息问题
)
```

**主要功能**:

- 支持单文件和目录扫描
- 自动识别文件类型和编程语言
- 智能忽略常见无关目录（node_modules, .git, venv 等）
- 提供详细的扫描结果统计

**示例**:

```python
from sensitive_check.scanner import scan_file, scan_directory

# 扫描单个文件
result = scan_file("./src/main.py")
print(f"Found {len(result.issues)} issues")

# 扫描目录
result = scan_directory("./src")
print(f"Scanned {result.files_scanned} files")
print(f"Found {result.total_issues} issues")
```

### `excel_exporter.py` - Excel导出模块

该模块负责将扫描结果导出为Excel格式的报告。

```python
from sensitive_check.excel_exporter import (
    export_to_excel,           # 导出Excel报告
    generate_report_filename,  # 生成报告文件名
)
```

**主要功能**:

- 生成包含汇总统计和详细问题的Excel报告
- 按严重级别分类创建多个Sheet
- 提供美观的格式化和颜色标记
- 包含检测时间戳和修复建议

**Excel报告结构**:

| Sheet名称 | 内容 |
|-----------|------|
| 汇总报告 | 扫描统计、按级别/类别分类统计 |
| 所有问题 | 按严重级别排序的所有问题列表 |
| 严重问题-CRITICAL | 仅CRITICAL级别问题 |
| 高危问题-HIGH | 仅HIGH级别问题 |
| 中级问题-MEDIUM | 仅MEDIUM级别问题 |
| 低级问题-LOW | 仅LOW级别问题 |

**示例**:

```python
from sensitive_check.excel_exporter import export_to_excel
from sensitive_check.scanner import scan_directory

# 扫描代码
result = scan_directory("./src")

# 导出Excel报告
export_to_excel(result, "report.xlsx", title="安全扫描报告")
```

**Excel报告字段**:

| 字段 | 说明 |
|------|------|
| 序号 | 问题编号 |
| 严重级别 | CRITICAL/HIGH/MEDIUM/LOW |
| 类别 | 敏感信息类别 |
| 文件路径 | 问题所在文件 |
| 行号 | 问题所在行 |
| 匹配内容 | 检测到的敏感信息片段 |
| 修复建议 | 安全修复建议 |

## 配置与自定义

### 自定义检测模式

可以通过编程方式添加自定义检测模式：

```python
from sensitive_check.patterns import SensitivePattern, Category, Severity
import re

# 创建自定义模式
custom_pattern = SensitivePattern(
    name="自定义密钥",
    category=Category.SECRET_KEY,
    severity=Severity.CRITICAL,
    pattern=re.compile(r"my_secret_key\s*=\s*['\"]?[^'\"]+['\"]?"),
    description="检测到自定义密钥",
    examples=["my_secret_key = 'abc123'"],
    recommendation="请使用环境变量存储密钥"
)

# 添加到模式列表
from sensitive_check.patterns import SENSITIVE_PATTERNS
SENSITIVE_PATTERNS.append(custom_pattern)
```

### 忽略特定目录

```bash
# 命令行指定忽略目录
sic scan ./src -i node_modules -i venv -i .venv

# 或在代码中
from sensitive_check.scanner import scan_directory
result = scan_directory("./src", ignore_dirs={"node_modules", "venv", ".git"})
```

### 过滤检测级别

```bash
# 只检测高危和严重级别
sic scan ./src -s critical,high

# 只检测密码相关
sic scan ./src -c password,api_key,token
```

## 示例与使用场景

### 使用测试样例

项目提供了丰富的测试样例，位于 `test_samples/` 目录：

```bash
# 测试 Python 敏感日志
sic scan test_samples/sample.py --show-context

# 测试敏感个人数据
sic scan test_samples/sample_personal.py --json

# 测试健康和设备数据
sic scan test_samples/sample_health_device.py

# 测试多种语言
sic scan test_samples/ --show-context

# 导出Excel报告
sic scan test_samples/ -x security_report.xlsx
```

### 测试样例说明

| 文件 | 说明 |
|------|------|
| `sample.py` | Python 密码、API密钥、身份证等敏感信息示例 |
| `sample.js` | JavaScript 敏感信息示例 |
| `SampleJava.java` | Java 日志敏感信息示例 |
| `sample.go` | Go 语言敏感信息示例 |
| `sample_personal.py` | 护照、驾驶证、社保等个人数据示例 |
| `sample_health_device.py` | 心率、血压、GPS、IMEI等健康设备数据示例 |

### CI/CD 集成

**GitHub Actions 示例**:

```yaml
name: Sensitive Info Check

on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install SIC
        run: |
          pip install git+https://github.com/RebornL/sensitive-info-check.git
      
      - name: Run SIC
        run: sic scan ./src -q --json > sic-report.json
        
      - name: Check Results
        run: |
          if [ $? -eq 1 ]; then
            echo "Found sensitive information in code!"
            cat sic-report.json
            exit 1
          fi
```

**Pre-commit Hook 示例**:

```bash
#!/bin/bash
# .git/hooks/pre-commit

# 安装工具
pip install -e . > /dev/null 2>&1

# 扫描暂存文件
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|js|ts|java|go)$')

if [ -n "$FILES" ]; then
    sic scan $FILES -q
    if [ $? -eq 1 ]; then
        echo "❌ 提交被拒绝：发现敏感信息"
        exit 1
    fi
fi

exit 0
```

## 测试说明

### 运行测试

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行所有测试
pytest tests/ -v

# 运行带覆盖率报告
pytest tests/ --cov=sensitive_check --cov-report=html
```

### 测试模块说明

| 测试文件 | 测试内容 |
|----------|----------|
| `test_patterns.py` | 敏感信息模式检测测试 |
| `test_detector.py` | 日志函数检测测试 |
| `test_scanner.py` | 代码扫描器测试 |
| `test_excel_exporter.py` | Excel导出功能测试 |

### 测试统计

```
tests/test_detector.py:        17 tests
tests/test_patterns.py:        13 tests
tests/test_scanner.py:         15 tests
tests/test_excel_exporter.py:  6 tests
───────────────────────────────────────
Total:                         51 tests
```

## 项目结构

```
sensitive-info-check/
├── sensitive_check/           # 核心代码目录
│   ├── __init__.py           # 包初始化，版本定义
│   ├── patterns.py           # 敏感信息模式定义（42种模式）
│   ├── detector.py           # 日志检测引擎（16种语言）
│   ├── scanner.py            # 代码扫描器
│   ├── excel_exporter.py     # Excel导出模块
│   └── cli.py                # 命令行接口
│
├── tests/                     # 单元测试
│   ├── __init__.py
│   ├── test_patterns.py      # 模式测试
│   ├── test_detector.py      # 检测器测试
│   ├── test_scanner.py       # 扫描器测试
│   └── test_excel_exporter.py # Excel导出测试
│
├── test_samples/              # 测试样例
│   ├── sample.py             # Python 敏感信息示例
│   ├── sample.js             # JavaScript 示例
│   ├── SampleJava.java       # Java 示例
│   ├── sample.go             # Go 示例
│   ├── sample_personal.py    # 个人数据示例
│   └── sample_health_device.py # 健康/设备数据示例
│
├── pyproject.toml            # 项目配置
├── .gitignore                # Git 忽略配置
└── README.md                 # 项目文档
```

### 文件说明

| 文件 | 行数 | 说明 |
|------|------|------|
| `patterns.py` | ~460 | 敏感信息模式定义，包含42种检测规则 |
| `detector.py` | ~350 | 日志检测引擎，支持16种编程语言 |
| `scanner.py` | ~470 | 代码扫描器，文件/目录扫描实现 |
| `excel_exporter.py` | ~280 | Excel报告导出模块 |
| `cli.py` | ~310 | 命令行接口，用户交互层 |

## 贡献指南

欢迎贡献代码、报告问题或提出建议！

### 如何贡献

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 代码规范

- 使用 Python 3.8+ 语法
- 遵循 PEP 8 编码规范
- 添加适当的文档字符串
- 为新功能编写测试用例

### 添加新的敏感信息模式

1. 在 `patterns.py` 中添加新的 `SensitivePattern`
2. 在 `tests/test_patterns.py` 中添加测试用例
3. 在 `README.md` 中更新文档
4. 在 `test_samples/` 中添加示例代码

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

```
MIT License

Copyright (c) 2024 RebornL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

**注意**: 本工具仅用于辅助检测代码中的敏感信息，不能保证检测出所有安全问题。建议配合代码审查、安全培训等措施共同保障代码安全。

如有问题或建议，欢迎提交 [Issue](https://github.com/RebornL/sensitive-info-check/issues)。