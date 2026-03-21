"""代码扫描器

扫描代码文件，检测敏感日志打印。
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .detector import (
    Language,
    LogMatch,
    detect_log_functions,
    detect_log_functions_multi_language,
)
from .patterns import (
    Category,
    SensitivePattern,
    SensitivePattern as SP,
    Severity,
    SENSITIVE_PATTERNS,
)


# 文件扩展名到语言的映射
EXTENSION_TO_LANGUAGE: Dict[str, Language] = {
    # Python
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".pyi": Language.PYTHON,

    # JavaScript/TypeScript
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".mts": Language.TYPESCRIPT,

    # Java/Kotlin
    ".java": Language.JAVA,
    ".kt": Language.KOTLIN,
    ".kts": Language.KOTLIN,

    # Go
    ".go": Language.GO,

    # Rust
    ".rs": Language.RUST,

    # C/C++
    ".c": Language.C,
    ".h": Language.C,
    ".cpp": Language.CPP,
    ".cxx": Language.CPP,
    ".cc": Language.CPP,
    ".hpp": Language.CPP,
    ".hxx": Language.CPP,

    # C#
    ".cs": Language.CSHARP,

    # PHP
    ".php": Language.PHP,

    # Ruby
    ".rb": Language.RUBY,
    ".rake": Language.RUBY,

    # Swift/Objective-C
    ".swift": Language.SWIFT,
    ".m": Language.OBJECTIVE_C,
    ".mm": Language.OBJECTIVE_C,
    ".h": Language.OBJECTIVE_C,  # 可能是OC头文件

    # Scala
    ".scala": Language.SCALA,
    ".sc": Language.SCALA,
}

# 默认忽略的目录
DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "build",
    "dist",
    "target",
    "bin",
    "obj",
    ".idea",
    ".vscode",
    "vendor",
    "Pods",
    ".gradle",
    "gradle",
    ".mvn",
}

# 默认忽略的文件
DEFAULT_IGNORE_FILES: Set[str] = {
    "*.min.js",
    "*.min.css",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "Cargo.lock",
    "poetry.lock",
    "*.pyc",
    "*.pyo",
    "*.class",
    "*.dll",
    "*.exe",
    "*.so",
    "*.dylib",
}


@dataclass
class SensitiveMatch:
    """敏感信息匹配结果"""
    line_number: int                          # 行号
    column_start: int                         # 开始列
    column_end: int                           # 结束列
    matched_text: str                         # 匹配的文本
    pattern: SensitivePattern                 # 匹配的模式
    context_before: str = ""                  # 前文上下文
    context_after: str = ""                   # 后文上下文


@dataclass
class LogSensitiveIssue:
    """日志中的敏感信息问题"""
    file_path: str                            # 文件路径
    line_number: int                          # 行号
    log_function: str                         # 日志函数名
    log_content: str                          # 日志内容
    sensitive_matches: List[SensitiveMatch]   # 敏感信息匹配列表
    severity: Severity                        # 严重级别（取最高的）
    language: Language                        # 编程语言


@dataclass
class FileScanResult:
    """文件扫描结果"""
    file_path: str                            # 文件路径
    language: Language                        # 编程语言
    total_lines: int                          # 总行数
    log_count: int                            # 日志语句数量
    issues: List[LogSensitiveIssue] = field(default_factory=list)
    error: Optional[str] = None               # 错误信息


@dataclass
class ScanResult:
    """扫描结果汇总"""
    files_scanned: int                        # 扫描文件数
    files_with_issues: int                    # 有问题的文件数
    total_issues: int                         # 总问题数
    issues_by_severity: Dict[Severity, int]   # 按严重级别分类
    issues_by_category: Dict[Category, int]  # 按类别分类
    file_results: List[FileScanResult] = field(default_factory=list)


def get_language_from_extension(file_path: str) -> Language:
    """根据文件扩展名获取编程语言"""
    ext = Path(file_path).suffix.lower()
    return EXTENSION_TO_LANGUAGE.get(ext, Language.UNKNOWN)


def should_ignore_path(
    path: str,
    ignore_dirs: Optional[Set[str]] = None,
    ignore_files: Optional[Set[str]] = None
) -> bool:
    """判断是否应该忽略该路径"""
    ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
    ignore_files = ignore_files or DEFAULT_IGNORE_FILES

    path_obj = Path(path)

    # 检查目录
    for part in path_obj.parts:
        if part in ignore_dirs:
            return True

    # 检查文件名模式
    filename = path_obj.name
    for pattern in ignore_files:
        if pattern.startswith("*"):
            if filename.endswith(pattern[1:]):
                return True
        elif filename == pattern:
            return True

    return False


def extract_log_content(line: str, log_match: LogMatch) -> str:
    """提取日志内容

    尝试提取日志函数调用中的参数内容
    """
    # 简单提取：从匹配位置开始，找到括号内的内容
    start_idx = log_match.column - 1
    content = line[start_idx:]

    # 尝试提取括号内容
    paren_count = 0
    result = []
    in_string = False
    string_char = None

    for i, char in enumerate(content):
        if char in ('"', "'") and (i == 0 or content[i-1] != '\\'):
            if not in_string:
                in_string = True
                string_char = char
            elif char == string_char:
                in_string = False
                string_char = None

        if not in_string:
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
                if paren_count == 0:
                    break

        if paren_count > 0:
            result.append(char)

    return ''.join(result)


def find_sensitive_in_text(
    text: str,
    patterns: Optional[List[SensitivePattern]] = None,
    severities: Optional[List[Severity]] = None,
    categories: Optional[List[Category]] = None
) -> List[SensitiveMatch]:
    """在文本中查找敏感信息

    Args:
        text: 要检查的文本
        patterns: 指定模式列表，None表示使用所有模式
        severities: 指定严重级别，None表示所有级别
        categories: 指定类别，None表示所有类别

    Returns:
        敏感信息匹配列表
    """
    if patterns is None:
        patterns = SENSITIVE_PATTERNS

    matches: List[SensitiveMatch] = []

    # 按严重级别和类别过滤模式
    filtered_patterns = []
    for pattern in patterns:
        if severities and pattern.severity not in severities:
            continue
        if categories and pattern.category not in categories:
            continue
        filtered_patterns.append(pattern)

    for pattern in filtered_patterns:
        for match in pattern.pattern.finditer(text):
            matches.append(SensitiveMatch(
                line_number=1,  # 调用者会设置正确的行号
                column_start=match.start() + 1,
                column_end=match.end() + 1,
                matched_text=match.group(),
                pattern=pattern
            ))

    return matches


def scan_file(
    file_path: str,
    patterns: Optional[List[SensitivePattern]] = None,
    severities: Optional[List[Severity]] = None,
    categories: Optional[List[Category]] = None,
    check_all_code: bool = False
) -> FileScanResult:
    """扫描单个文件

    Args:
        file_path: 文件路径
        patterns: 指定模式列表
        severities: 指定严重级别
        categories: 指定类别
        check_all_code: 是否检查所有代码，而不仅仅是日志语句

    Returns:
        文件扫描结果
    """
    result = FileScanResult(
        file_path=file_path,
        language=Language.UNKNOWN,
        total_lines=0,
        log_count=0
    )

    try:
        # 获取语言类型
        result.language = get_language_from_extension(file_path)
        if result.language == Language.UNKNOWN:
            return result

        # 读取文件
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        lines = content.split('\n')
        result.total_lines = len(lines)

        # 如果检查所有代码
        if check_all_code:
            all_matches = find_sensitive_in_text(
                content, patterns, severities, categories
            )

            if all_matches:
                # 计算行号
                line_starts = [0]
                for line in lines[:-1]:
                    line_starts.append(line_starts[-1] + len(line) + 1)

                def get_line_number(pos: int) -> int:
                    for i, start in enumerate(line_starts):
                        if start > pos:
                            return i
                    return len(line_starts)

                for match in all_matches:
                    line_num = get_line_number(match.column_start - 1)
                    match.line_number = line_num

                issue = LogSensitiveIssue(
                    file_path=file_path,
                    line_number=1,
                    log_function="(全文件扫描)",
                    log_content="(检查所有代码)",
                    sensitive_matches=all_matches,
                    severity=max(m.pattern.severity for m in all_matches),
                    language=result.language
                )
                result.issues.append(issue)
                result.log_count = 1

            return result

        # 检测日志函数
        log_matches = detect_log_functions(content, result.language)
        result.log_count = len(log_matches)

        # 检查每个日志语句中的敏感信息
        for log_match in log_matches:
            line_idx = log_match.line_number - 1
            if line_idx >= len(lines):
                continue

            # 获取日志行及其上下文
            line = lines[line_idx]
            context_lines = []

            # 获取上下文（多行日志支持）
            start_idx = max(0, line_idx - 2)
            end_idx = min(len(lines), line_idx + 3)

            # 提取日志内容区域
            log_content = extract_log_content(line, log_match)

            # 也检查当前行附近的上下文
            context_text = '\n'.join(lines[start_idx:end_idx])

            # 在日志内容中查找敏感信息
            sensitive_matches = find_sensitive_in_text(
                log_content or line,  # 如果提取失败，使用整行
                patterns,
                severities,
                categories
            )

            if sensitive_matches:
                # 更新行号
                for sm in sensitive_matches:
                    sm.line_number = log_match.line_number
                    sm.context_before = '\n'.join(lines[max(0, line_idx-2):line_idx])
                    sm.context_after = '\n'.join(lines[line_idx+1:min(len(lines), line_idx+3)])

                issue = LogSensitiveIssue(
                    file_path=file_path,
                    line_number=log_match.line_number,
                    log_function=log_match.function_name,
                    log_content=log_content or line,
                    sensitive_matches=sensitive_matches,
                    severity=max(m.pattern.severity for m in sensitive_matches),
                    language=result.language
                )
                result.issues.append(issue)

    except Exception as e:
        result.error = str(e)

    return result


def scan_directory(
    directory: str,
    patterns: Optional[List[SensitivePattern]] = None,
    severities: Optional[List[Severity]] = None,
    categories: Optional[List[Category]] = None,
    ignore_dirs: Optional[Set[str]] = None,
    ignore_files: Optional[Set[str]] = None,
    file_extensions: Optional[List[str]] = None,
    check_all_code: bool = False,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
) -> ScanResult:
    """扫描目录

    Args:
        directory: 目录路径
        patterns: 指定模式列表
        severities: 指定严重级别
        categories: 指定类别
        ignore_dirs: 忽略的目录
        ignore_files: 忽略的文件
        file_extensions: 要扫描的文件扩展名
        check_all_code: 是否检查所有代码
        max_file_size: 最大文件大小

    Returns:
        扫描结果
    """
    result = ScanResult(
        files_scanned=0,
        files_with_issues=0,
        total_issues=0,
        issues_by_severity={s: 0 for s in Severity},
        issues_by_category={c: 0 for c in Category}
    )

    ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
    ignore_files = ignore_files or DEFAULT_IGNORE_FILES

    # 遍历目录
    for root, dirs, files in os.walk(directory):
        # 过滤目录
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith('.')]

        for filename in files:
            file_path = os.path.join(root, filename)

            # 检查是否忽略
            if should_ignore_path(file_path, ignore_dirs, ignore_files):
                continue

            # 检查文件扩展名
            if file_extensions:
                ext = Path(file_path).suffix.lower()
                if ext not in file_extensions:
                    continue

            # 检查文件大小
            try:
                if os.path.getsize(file_path) > max_file_size:
                    continue
            except OSError:
                continue

            # 扫描文件
            file_result = scan_file(
                file_path,
                patterns,
                severities,
                categories,
                check_all_code
            )

            result.files_scanned += 1
            result.file_results.append(file_result)

            if file_result.issues:
                result.files_with_issues += 1
                result.total_issues += len(file_result.issues)

                for issue in file_result.issues:
                    result.issues_by_severity[issue.severity] += 1
                    for match in issue.sensitive_matches:
                        result.issues_by_category[match.pattern.category] += 1

    return result