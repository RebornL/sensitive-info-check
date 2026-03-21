"""日志检测引擎

检测代码中的日志打印语句。
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Pattern, Set, Tuple


class Language(Enum):
    """支持的编程语言"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    KOTLIN = "kotlin"
    GO = "go"
    RUST = "rust"
    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    PHP = "php"
    RUBY = "ruby"
    SWIFT = "swift"
    OBJECTIVE_C = "objective_c"
    SCALA = "scala"
    UNKNOWN = "unknown"


@dataclass
class LogFunction:
    """日志函数定义"""
    name: str                           # 函数名
    patterns: List[Pattern]             # 匹配模式列表
    description: str                    # 描述
    extract_content_pattern: Optional[Pattern] = None  # 提取内容的模式


# 各语言的日志函数定义
LOG_FUNCTIONS: Dict[Language, List[LogFunction]] = {
    Language.PYTHON: [
        LogFunction(
            name="print",
            patterns=[
                re.compile(r"\bprint\s*\("),
            ],
            description="Python print函数"
        ),
        LogFunction(
            name="logging",
            patterns=[
                re.compile(r"\b(logging\.(debug|info|warning|error|critical|exception)\s*\()"),
                re.compile(r"\blogger\.(debug|info|warning|error|critical|exception)\s*\("),
                re.compile(r"\blog\.(debug|info|warning|error|critical|exception)\s*\("),
            ],
            description="Python logging模块"
        ),
        LogFunction(
            name="pprint",
            patterns=[
                re.compile(r"\bpprint\.pprint\s*\("),
                re.compile(r"\bpprint\s*\("),
            ],
            description="Python pprint模块"
        ),
        LogFunction(
            name="syslog",
            patterns=[
                re.compile(r"\bsyslog\.(syslog|LOG_INFO|LOG_DEBUG|LOG_WARNING|LOG_ERROR)\s*\("),
            ],
            description="Python syslog模块"
        ),
    ],

    Language.JAVASCRIPT: [
        LogFunction(
            name="console",
            patterns=[
                re.compile(r"\bconsole\.(log|info|warn|error|debug|trace|dir|table)\s*\("),
            ],
            description="JavaScript console对象"
        ),
        LogFunction(
            name="alert",
            patterns=[
                re.compile(r"\balert\s*\("),
            ],
            description="JavaScript alert函数"
        ),
        LogFunction(
            name="document.write",
            patterns=[
                re.compile(r"\bdocument\.write\s*\("),
                re.compile(r"\bdocument\.writeln\s*\("),
            ],
            description="JavaScript document.write"
        ),
    ],

    Language.TYPESCRIPT: [
        LogFunction(
            name="console",
            patterns=[
                re.compile(r"\bconsole\.(log|info|warn|error|debug|trace|dir|table)\s*\("),
            ],
            description="TypeScript console对象"
        ),
    ],

    Language.JAVA: [
        LogFunction(
            name="System.out",
            patterns=[
                re.compile(r"\bSystem\.out\.print(ln)?\s*\("),
                re.compile(r"\bSystem\.err\.print(ln)?\s*\("),
            ],
            description="Java System.out/err"
        ),
        LogFunction(
            name="Log4j",
            patterns=[
                re.compile(r"\blog(ger)?\.(debug|info|warn|error|fatal|trace)\s*\("),
                re.compile(r"\bLogger\.(debug|info|warn|error|fatal|trace)\s*\("),
                re.compile(r"\bLoggerFactory\.getLogger"),
            ],
            description="Log4j/SLF4J日志框架"
        ),
        LogFunction(
            name="Android Log",
            patterns=[
                re.compile(r"\bLog\.(v|d|i|w|e|wtf)\s*\("),
            ],
            description="Android Log类"
        ),
        LogFunction(
            name="java.util.logging",
            patterns=[
                re.compile(r"\bLogger\.(fine|finer|finest|info|warning|severe)\s*\("),
                re.compile(r"\blogger\.(fine|finer|finest|info|warning|severe)\s*\("),
            ],
            description="Java util logging"
        ),
    ],

    Language.KOTLIN: [
        LogFunction(
            name="println",
            patterns=[
                re.compile(r"\bprintln\s*\("),
                re.compile(r"\bprint\s*\("),
            ],
            description="Kotlin print/println"
        ),
        LogFunction(
            name="Android Log",
            patterns=[
                re.compile(r"\bLog\.(v|d|i|w|e|wtf)\s*\("),
            ],
            description="Android Log类"
        ),
    ],

    Language.GO: [
        LogFunction(
            name="fmt",
            patterns=[
                re.compile(r"\bfmt\.Print(ln)?\s*\("),
                re.compile(r"\bfmt\.Println\s*\("),
                re.compile(r"\bfmt\.Printf\s*\("),
            ],
            description="Go fmt包"
        ),
        LogFunction(
            name="log",
            patterns=[
                re.compile(r"\blog\.(Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln)\s*\("),
            ],
            description="Go log包"
        ),
    ],

    Language.RUST: [
        LogFunction(
            name="println",
            patterns=[
                re.compile(r"\bprintln!\s*\("),
                re.compile(r"\bprint!\s*\("),
                re.compile(r"\beprintln!\s*\("),
                re.compile(r"\beprint!\s*\("),
            ],
            description="Rust println/print宏"
        ),
        LogFunction(
            name="log crate",
            patterns=[
                re.compile(r"\b(log|trace|debug|info|warn|error)!\s*\("),
            ],
            description="Rust log crate"
        ),
    ],

    Language.C: [
        LogFunction(
            name="printf",
            patterns=[
                re.compile(r"\bprintf\s*\("),
                re.compile(r"\bfprintf\s*\("),
                re.compile(r"\bsprintf\s*\("),
                re.compile(r"\bsnprintf\s*\("),
            ],
            description="C printf系列函数"
        ),
        LogFunction(
            name="puts",
            patterns=[
                re.compile(r"\bputs\s*\("),
                re.compile(r"\bfputs\s*\("),
            ],
            description="C puts函数"
        ),
        LogFunction(
            name="syslog",
            patterns=[
                re.compile(r"\bsyslog\s*\("),
            ],
            description="C syslog函数"
        ),
    ],

    Language.CPP: [
        LogFunction(
            name="iostream",
            patterns=[
                re.compile(r"\bstd::cout\s*<<"),
                re.compile(r"\bstd::cerr\s*<<"),
                re.compile(r"\bstd::clog\s*<<"),
                re.compile(r"\bcout\s*<<"),
                re.compile(r"\bcerr\s*<<"),
            ],
            description="C++ iostream"
        ),
        LogFunction(
            name="printf",
            patterns=[
                re.compile(r"\bprintf\s*\("),
                re.compile(r"\bfprintf\s*\("),
            ],
            description="C++ printf"
        ),
    ],

    Language.CSHARP: [
        LogFunction(
            name="Console",
            patterns=[
                re.compile(r"\bConsole\.Write(Line)?\s*\("),
            ],
            description="C# Console类"
        ),
        LogFunction(
            name="Debug",
            patterns=[
                re.compile(r"\bDebug\.Write(Line)?\s*\("),
                re.compile(r"\bTrace\.Write(Line)?\s*\("),
            ],
            description="C# Debug/Trace类"
        ),
        LogFunction(
            name="Serilog/NLog",
            patterns=[
                re.compile(r"\bLog\.(Debug|Information|Warning|Error|Fatal)\s*\("),
                re.compile(r"\blogger\.(Debug|Info|Warn|Error|Fatal)\s*\("),
            ],
            description="C# Serilog/NLog"
        ),
    ],

    Language.PHP: [
        LogFunction(
            name="echo/print",
            patterns=[
                re.compile(r"\becho\s+"),
                re.compile(r"\bprint\s*\("),
                re.compile(r"\bprint_r\s*\("),
                re.compile(r"\bvar_dump\s*\("),
            ],
            description="PHP echo/print"
        ),
        LogFunction(
            name="error_log",
            patterns=[
                re.compile(r"\berror_log\s*\("),
            ],
            description="PHP error_log"
        ),
        LogFunction(
            name="syslog",
            patterns=[
                re.compile(r"\bsyslog\s*\("),
            ],
            description="PHP syslog"
        ),
    ],

    Language.RUBY: [
        LogFunction(
            name="puts",
            patterns=[
                re.compile(r"\bputs\s+"),
                re.compile(r"\bprint\s+"),
                re.compile(r"\bp\s+"),
            ],
            description="Ruby puts/print"
        ),
        LogFunction(
            name="Logger",
            patterns=[
                re.compile(r"\blogger\.(debug|info|warn|error|fatal)\s*\("),
                re.compile(r"\bRails\.logger\.(debug|info|warn|error|fatal)\s*\("),
            ],
            description="Ruby Logger"
        ),
    ],

    Language.SWIFT: [
        LogFunction(
            name="print",
            patterns=[
                re.compile(r"\bprint\s*\("),
                re.compile(r"\bdebugPrint\s*\("),
                re.compile(r"\bdump\s*\("),
            ],
            description="Swift print函数"
        ),
        LogFunction(
            name="os_log",
            patterns=[
                re.compile(r"\bos_log\.(debug|info|error|fault)\s*\("),
                re.compile(r"\bOSLog\.(debug|info|error|fault)\s*\("),
            ],
            description="Swift os_log"
        ),
    ],

    Language.OBJECTIVE_C: [
        LogFunction(
            name="NSLog",
            patterns=[
                re.compile(r"\bNSLog\s*\("),
            ],
            description="Objective-C NSLog"
        ),
        LogFunction(
            name="printf",
            patterns=[
                re.compile(r"\bprintf\s*\("),
                re.compile(r"\bfprintf\s*\("),
            ],
            description="Objective-C printf"
        ),
    ],

    Language.SCALA: [
        LogFunction(
            name="println",
            patterns=[
                re.compile(r"\bprintln\s*\("),
                re.compile(r"\bprint\s*\("),
            ],
            description="Scala println"
        ),
        LogFunction(
            name="Log4j/SLF4J",
            patterns=[
                re.compile(r"\blog(ger)?\.(debug|info|warn|error|trace)\s*\("),
            ],
            description="Scala Log4j/SLF4J"
        ),
    ],
}


@dataclass
class LogMatch:
    """日志匹配结果"""
    line_number: int                   # 行号
    column: int                        # 列号
    match_text: str                    # 匹配的文本
    function_name: str                 # 日志函数名
    language: Language                 # 语言
    description: str                   # 描述
    content: str = ""                  # 日志内容（提取的）


def detect_log_functions(
    code: str,
    language: Language
) -> List[LogMatch]:
    """检测代码中的日志函数调用

    Args:
        code: 源代码字符串
        language: 编程语言

    Returns:
        日志匹配列表
    """
    matches: List[LogMatch] = []
    lines = code.split('\n')

    # 获取该语言的日志函数
    log_funcs = LOG_FUNCTIONS.get(language, [])

    for line_num, line in enumerate(lines, 1):
        for log_func in log_funcs:
            for pattern in log_func.patterns:
                for match in pattern.finditer(line):
                    matches.append(LogMatch(
                        line_number=line_num,
                        column=match.start() + 1,
                        match_text=match.group(),
                        function_name=log_func.name,
                        language=language,
                        description=log_func.description,
                        content=line.strip()
                    ))

    return matches


def detect_log_functions_multi_language(
    code: str,
    languages: Optional[List[Language]] = None
) -> List[LogMatch]:
    """检测代码中的日志函数调用（支持多语言）

    Args:
        code: 源代码字符串
        languages: 要检测的语言列表，None表示检测所有语言

    Returns:
        日志匹配列表
    """
    if languages is None:
        languages = list(Language)

    all_matches: List[LogMatch] = []
    for lang in languages:
        if lang != Language.UNKNOWN:
            matches = detect_log_functions(code, lang)
            all_matches.extend(matches)

    return all_matches


def get_supported_languages() -> List[Language]:
    """获取支持的编程语言列表"""
    return [lang for lang in Language if lang != Language.UNKNOWN]