"""测试代码扫描器"""

import os
import tempfile
import pytest
from sensitive_check.scanner import (
    Language,
    SensitiveMatch,
    LogSensitiveIssue,
    FileScanResult,
    ScanResult,
    get_language_from_extension,
    should_ignore_path,
    find_sensitive_in_text,
    scan_file,
    scan_directory,
    extract_log_content,
    DEFAULT_IGNORE_DIRS,
    DEFAULT_IGNORE_FILES,
)
from sensitive_check.patterns import Severity, Category


class TestScanner:
    """测试代码扫描器"""

    def test_get_language_from_extension(self):
        """测试从扩展名获取语言"""
        assert get_language_from_extension("test.py") == Language.PYTHON
        assert get_language_from_extension("test.js") == Language.JAVASCRIPT
        assert get_language_from_extension("test.ts") == Language.TYPESCRIPT
        assert get_language_from_extension("test.java") == Language.JAVA
        assert get_language_from_extension("test.go") == Language.GO
        assert get_language_from_extension("test.rs") == Language.RUST
        assert get_language_from_extension("test.c") == Language.C
        assert get_language_from_extension("test.cpp") == Language.CPP
        assert get_language_from_extension("test.cs") == Language.CSHARP
        assert get_language_from_extension("test.php") == Language.PHP
        assert get_language_from_extension("test.rb") == Language.RUBY
        assert get_language_from_extension("test.swift") == Language.SWIFT
        assert get_language_from_extension("test.m") == Language.OBJECTIVE_C
        assert get_language_from_extension("test.scala") == Language.SCALA
        assert get_language_from_extension("test.txt") == Language.UNKNOWN

    def test_should_ignore_path_dirs(self):
        """测试忽略目录"""
        assert should_ignore_path("node_modules/package.json")
        assert should_ignore_path(".git/config")
        assert should_ignore_path("venv/lib/site-packages")
        assert should_ignore_path("build/output.js")
        assert should_ignore_path("dist/bundle.js")

    def test_should_ignore_path_files(self):
        """测试忽略文件"""
        assert should_ignore_path("app.min.js")
        assert should_ignore_path("package-lock.json")
        assert should_ignore_path("test.pyc")

    def test_should_not_ignore_normal_paths(self):
        """测试不忽略正常路径"""
        assert not should_ignore_path("src/main.py")
        assert not should_ignore_path("lib/utils.js")
        assert not should_ignore_path("app/index.ts")

    def test_find_sensitive_in_text_password(self):
        """测试查找密码"""
        text = "password = 'mySecretPassword123'"
        matches = find_sensitive_in_text(text)
        password_matches = [m for m in matches if m.pattern.category == Category.PASSWORD]
        assert len(password_matches) > 0

    def test_find_sensitive_in_text_api_key(self):
        """测试查找API密钥"""
        text = "api_key = 'sk-1234567890abcdef123456'"
        matches = find_sensitive_in_text(text)
        api_key_matches = [m for m in matches if m.pattern.category == Category.API_KEY]
        assert len(api_key_matches) > 0

    def test_find_sensitive_in_text_phone(self):
        """测试查找手机号"""
        text = "手机号：13812345678"
        matches = find_sensitive_in_text(text)
        phone_matches = [m for m in matches if m.pattern.category == Category.PHONE]
        assert len(phone_matches) > 0

    def test_find_sensitive_in_text_email(self):
        """测试查找邮箱"""
        text = "邮箱：user@example.com"
        matches = find_sensitive_in_text(text)
        email_matches = [m for m in matches if m.pattern.category == Category.EMAIL]
        assert len(email_matches) > 0

    def test_find_sensitive_in_text_severity_filter(self):
        """测试严重级别过滤"""
        text = "password = 'secret123' 手机号：13812345678"
        critical_matches = find_sensitive_in_text(text, severities=[Severity.CRITICAL])
        for m in critical_matches:
            assert m.pattern.severity == Severity.CRITICAL

    def test_find_sensitive_in_text_category_filter(self):
        """测试类别过滤"""
        text = "password = 'secret123' 手机号：13812345678"
        password_matches = find_sensitive_in_text(text, categories=[Category.PASSWORD])
        for m in password_matches:
            assert m.pattern.category == Category.PASSWORD

    def test_scan_file_with_sensitive_log(self):
        """测试扫描包含敏感日志的文件"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
def login():
    password = "admin123"
    print(f"Password: {password}")
    api_key = "sk-1234567890abcdef"
    logging.info(f"API Key: {api_key}")
""")
            f.flush()
            temp_path = f.name

        try:
            result = scan_file(temp_path)
            assert result.language == Language.PYTHON
            assert result.log_count >= 2
            assert len(result.issues) > 0
        finally:
            os.unlink(temp_path)

    def test_scan_file_without_sensitive(self):
        """测试扫描不包含敏感信息的文件"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
def hello():
    name = "World"
    print(f"Hello, {name}!")
""")
            f.flush()
            temp_path = f.name

        try:
            result = scan_file(temp_path)
            assert result.language == Language.PYTHON
            assert len(result.issues) == 0
        finally:
            os.unlink(temp_path)

    def test_scan_file_all_code_mode(self):
        """测试全代码扫描模式"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
password = "admin123"
api_key = "sk-1234567890abcdef"
# 没有日志语句
""")
            f.flush()
            temp_path = f.name

        try:
            result = scan_file(temp_path, check_all_code=True)
            assert result.language == Language.PYTHON
            assert len(result.issues) > 0
        finally:
            os.unlink(temp_path)

    def test_scan_directory(self):
        """测试扫描目录"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # 创建测试文件
            py_file = os.path.join(temp_dir, "test.py")
            with open(py_file, 'w') as f:
                f.write('print(f"Password: mySecretPass123")')

            js_file = os.path.join(temp_dir, "test.js")
            with open(js_file, 'w') as f:
                f.write('console.log("api_key: sk-1234567890abcdefghijklmnop")')

            # 创建忽略目录
            ignore_dir = os.path.join(temp_dir, "node_modules")
            os.makedirs(ignore_dir)
            with open(os.path.join(ignore_dir, "ignore.js"), 'w') as f:
                f.write('console.log("Should be ignored")')

            result = scan_directory(temp_dir)

            # 应该只扫描2个文件
            assert result.files_scanned == 2
            assert result.total_issues >= 2

    def test_extract_log_content_simple(self):
        """测试提取简单日志内容"""
        from sensitive_check.detector import LogMatch, Language
        line = 'print("Hello, World!")'
        log_match = LogMatch(
            line_number=1,
            column=1,
            match_text='print(',
            function_name='print',
            language=Language.PYTHON,
            description='Test'
        )
        content = extract_log_content(line, log_match)
        assert 'Hello, World!' in content