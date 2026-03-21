"""命令行接口

提供命令行工具入口。
"""

import json
import sys
from pathlib import Path
from typing import List, Optional

import click
from colorama import init as colorama_init
from colorama import Fore, Style

from . import __version__
from .patterns import Severity, Category, SENSITIVE_PATTERNS, get_patterns_by_severities, get_patterns_by_category
from .scanner import (
    scan_directory,
    scan_file,
    FileScanResult,
    LogSensitiveIssue,
    SensitiveMatch,
    ScanResult,
)
from .excel_exporter import export_to_excel, generate_report_filename

# 初始化colorama
colorama_init()


def format_severity(severity: Severity) -> str:
    """格式化严重级别显示"""
    colors = {
        Severity.CRITICAL: Fore.RED,
        Severity.HIGH: Fore.YELLOW,
        Severity.MEDIUM: Fore.BLUE,
        Severity.LOW: Fore.GREEN,
    }
    color = colors.get(severity, Fore.WHITE)
    return f"{color}{severity.label.upper()}{Style.RESET_ALL}"


def print_issue(issue: LogSensitiveIssue, show_context: bool = False, show_code: bool = True):
    """打印单个问题"""
    # 文件路径和行号
    location = f"{issue.file_path}:{issue.line_number}"
    click.echo(f"\n  {Fore.CYAN}*{Style.RESET_ALL} {location}")

    # 严重级别和日志函数
    severity_str = format_severity(issue.severity)
    click.echo(f"    级别: {severity_str}  |  日志函数: {issue.log_function}")

    # 敏感信息详情
    for match in issue.sensitive_matches:
        pattern = match.pattern
        click.echo(f"    {Fore.YELLOW}-{Style.RESET_ALL} [{pattern.category.value}] {pattern.name}")
        click.echo(f"      匹配内容: {Fore.RED}{match.matched_text[:50]}{'...' if len(match.matched_text) > 50 else ''}{Style.RESET_ALL}")
        if pattern.recommendation:
            click.echo(f"      建议: {pattern.recommendation}")

    # 显示代码上下文
    if show_code:
        try:
            with open(issue.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                line_idx = issue.line_number - 1
                if 0 <= line_idx < len(lines):
                    # 显示前后几行
                    start = max(0, line_idx - 1)
                    end = min(len(lines), line_idx + 2)
                    click.echo(f"    {Fore.WHITE}代码:{Style.RESET_ALL}")
                    for i in range(start, end):
                        prefix = "→ " if i == line_idx else "  "
                        line_num = i + 1
                        click.echo(f"      {Fore.WHITE}{prefix}{line_num:4d} |{Style.RESET_ALL} {lines[i].rstrip()}")
        except Exception:
            pass


def print_summary(result: ScanResult):
    """打印扫描摘要"""
    click.echo(f"\n{'='*60}")
    click.echo(f"{Fore.CYAN}扫描摘要{Style.RESET_ALL}")
    click.echo(f"{'='*60}")

    click.echo(f"\n  扫描文件数: {result.files_scanned}")
    click.echo(f"  发现问题文件: {Fore.YELLOW if result.files_with_issues > 0 else Fore.GREEN}{result.files_with_issues}{Style.RESET_ALL}")
    click.echo(f"  问题总数: {Fore.RED if result.total_issues > 0 else Fore.GREEN}{result.total_issues}{Style.RESET_ALL}")

    # 按严重级别统计
    click.echo(f"\n  {Fore.WHITE}按严重级别:{Style.RESET_ALL}")
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = result.issues_by_severity.get(severity, 0)
        if count > 0:
            click.echo(f"    {format_severity(severity)}: {count}")

    # 按类别统计
    click.echo(f"\n  {Fore.WHITE}按敏感信息类别:{Style.RESET_ALL}")
    for category, count in result.issues_by_category.items():
        if count > 0:
            click.echo(f"    {category.value}: {count}")


def print_json_result(result: ScanResult):
    """输出JSON格式结果"""
    output = {
        "summary": {
            "files_scanned": result.files_scanned,
            "files_with_issues": result.files_with_issues,
            "total_issues": result.total_issues,
            "issues_by_severity": {
                s.value: result.issues_by_severity.get(s, 0)
                for s in Severity
            },
            "issues_by_category": {
                c.value: result.issues_by_category.get(c, 0)
                for c in Category
            }
        },
        "issues": []
    }

    for file_result in result.file_results:
        for issue in file_result.issues:
            issue_data = {
                "file": issue.file_path,
                "line": issue.line_number,
                "log_function": issue.log_function,
                "severity": issue.severity.label,
                "language": issue.language.value,
                "sensitive_matches": [
                    {
                        "category": m.pattern.category.value,
                        "type": m.pattern.name,
                        "matched_text": m.matched_text,
                        "description": m.pattern.description,
                        "recommendation": m.pattern.recommendation
                    }
                    for m in issue.sensitive_matches
                ]
            }
            output["issues"].append(issue_data)

    click.echo(json.dumps(output, ensure_ascii=False, indent=2))


def parse_severities(severity_str: str) -> List[Severity]:
    """解析严重级别参数"""
    severity_map = {
        'critical': Severity.CRITICAL,
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
    }

    if not severity_str:
        return list(Severity)

    severities = []
    for s in severity_str.split(','):
        s = s.strip().lower()
        if s in severity_map:
            severities.append(severity_map[s])

    return severities if severities else list(Severity)


def parse_categories(category_str: str) -> List[Category]:
    """解析类别参数"""
    if not category_str:
        return list(Category)

    categories = []
    for c in category_str.split(','):
        c = c.strip().lower()
        try:
            categories.append(Category(c))
        except ValueError:
            pass

    return categories if categories else list(Category)


@click.group()
@click.version_option(version=__version__, prog_name="sensitive-info-check")
def main():
    """敏感信息检查工具 - 检查代码中是否存在敏感日志打印"""
    pass


@main.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('-r', '--recursive', is_flag=True, default=True, help='递归扫描目录')
@click.option('-a', '--all-code', is_flag=True, default=False, help='检查所有代码，不仅仅是日志语句')
@click.option('-s', '--severity', default='', help='过滤严重级别 (critical,high,medium,low)，逗号分隔')
@click.option('-c', '--category', default='', help='过滤类别 (password,api_key,token等)，逗号分隔')
@click.option('-i', '--ignore-dir', multiple=True, help='忽略的目录（可多次指定）')
@click.option('-e', '--extension', multiple=True, help='扫描的文件扩展名（可多次指定）')
@click.option('--show-context', is_flag=True, help='显示代码上下文')
@click.option('--json', 'json_output', is_flag=True, help='JSON格式输出')
@click.option('-x', '--excel', 'excel_output', default='', help='导出Excel报告到指定路径')
@click.option('--no-summary', is_flag=True, help='不显示摘要')
@click.option('-q', '--quiet', is_flag=True, help='静默模式，只显示有问题的地方')
def scan(
    path: str,
    recursive: bool,
    all_code: bool,
    severity: str,
    category: str,
    ignore_dir: tuple,
    extension: tuple,
    show_context: bool,
    json_output: bool,
    excel_output: str,
    no_summary: bool,
    quiet: bool
):
    """扫描文件或目录中的敏感日志

    示例:
        sic scan ./src                    # 扫描src目录
        sic scan ./src -s critical,high  # 只扫描高危级别
        sic scan ./src -a                # 扫描所有代码
        sic scan ./src --json            # JSON格式输出
        sic scan ./src -x report.xlsx    # 导出Excel报告
    """
    path_obj = Path(path)

    # 解析参数
    severities = parse_severities(severity)
    categories = parse_categories(category)
    patterns = get_patterns_by_severities(severities) if severity else None

    # 忽略目录
    ignore_dirs = set(ignore_dir) if ignore_dir else None

    # 文件扩展名
    extensions = list(extension) if extension else None

    # 扫描
    if path_obj.is_file():
        result = scan_file(
            str(path_obj),
            patterns=patterns,
            severities=severities,
            categories=categories,
            check_all_code=all_code
        )
        # 包装成ScanResult
        scan_result = ScanResult(
            files_scanned=1,
            files_with_issues=1 if result.issues else 0,
            total_issues=len(result.issues),
            issues_by_severity={s: 0 for s in Severity},
            issues_by_category={c: 0 for c in Category},
            file_results=[result]
        )
        for issue in result.issues:
            scan_result.issues_by_severity[issue.severity] += 1
            for match in issue.sensitive_matches:
                scan_result.issues_by_category[match.pattern.category] += 1
    else:
        scan_result = scan_directory(
            str(path_obj),
            patterns=patterns,
            severities=severities,
            categories=categories,
            ignore_dirs=ignore_dirs,
            file_extensions=extensions,
            check_all_code=all_code
        )

    # 输出结果
    if json_output:
        print_json_result(scan_result)
    else:
        if not quiet:
            click.echo(f"\n{Fore.CYAN}敏感信息检查工具 v{__version__}{Style.RESET_ALL}")
            click.echo(f"{'='*60}")
            click.echo(f"扫描路径: {path}")

        # 打印问题
        for file_result in scan_result.file_results:
            if file_result.issues:
                for issue in file_result.issues:
                    print_issue(issue, show_context, show_code=show_context)
                    click.echo("")

        # 打印摘要
        if not no_summary and not quiet:
            print_summary(scan_result)

    # 导出Excel报告
    if excel_output is not None and excel_output != '':
        try:
            # 如果只传入目录或文件名，自动生成完整路径
            output_path = excel_output
            if not output_path.endswith('.xlsx'):
                output_path = output_path + '.xlsx'

            export_to_excel(scan_result, output_path)

            if not quiet:
                click.echo(f"\n{Fore.GREEN}Excel报告已生成: {output_path}{Style.RESET_ALL}")
        except Exception as e:
            click.echo(f"\n{Fore.RED}导出Excel失败: {str(e)}{Style.RESET_ALL}", err=True)

    # 返回码
    sys.exit(1 if scan_result.total_issues > 0 else 0)


@main.command()
def list_patterns():
    """列出所有支持的敏感信息模式"""
    click.echo(f"\n{Fore.CYAN}支持的敏感信息模式{Style.RESET_ALL}")
    click.echo(f"{'='*60}\n")

    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        patterns = [p for p in SENSITIVE_PATTERNS if p.severity == severity]
        if patterns:
            click.echo(f"{format_severity(severity)}")
            click.echo("-" * 40)
            for pattern in patterns:
                click.echo(f"\n  {Fore.WHITE}{pattern.name}{Style.RESET_ALL}")
                click.echo(f"  类别: {pattern.category.value}")
                click.echo(f"  描述: {pattern.description}")
                if pattern.examples:
                    click.echo(f"  示例:")
                    for example in pattern.examples:
                        click.echo(f"    - {Fore.YELLOW}{example}{Style.RESET_ALL}")
                if pattern.recommendation:
                    click.echo(f"  建议: {Fore.GREEN}{pattern.recommendation}{Style.RESET_ALL}")
            click.echo("")


@main.command()
def list_languages():
    """列出所有支持的编程语言"""
    from .detector import get_supported_languages, LOG_FUNCTIONS

    click.echo(f"\n{Fore.CYAN}支持的编程语言{Style.RESET_ALL}")
    click.echo(f"{'='*60}\n")

    for lang in get_supported_languages():
        funcs = LOG_FUNCTIONS.get(lang, [])
        click.echo(f"{Fore.WHITE}{lang.value}{Style.RESET_ALL}")
        if funcs:
            func_names = [f.name for f in funcs]
            click.echo(f"  日志函数: {', '.join(func_names)}")
        click.echo("")


if __name__ == '__main__':
    main()