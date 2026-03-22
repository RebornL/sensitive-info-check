"""配置加载器测试"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from sensitive_check.config_loader import (
    ConfigLoadError,
    PatternValidationError,
    parse_severity,
    parse_category,
    parse_regex_flags,
    create_pattern_from_dict,
    load_json_config,
    load_patterns_from_config,
    load_custom_patterns,
    merge_patterns,
    get_all_patterns,
    validate_config_file,
)
from sensitive_check.patterns import Severity, Category, SensitivePattern, SENSITIVE_PATTERNS


class TestParseSeverity:
    """测试严重级别解析"""

    def test_parse_severity_critical(self):
        assert parse_severity("critical") == Severity.CRITICAL
        assert parse_severity("CRITICAL") == Severity.CRITICAL
        assert parse_severity("4") == Severity.CRITICAL

    def test_parse_severity_high(self):
        assert parse_severity("high") == Severity.HIGH
        assert parse_severity("HIGH") == Severity.HIGH
        assert parse_severity("3") == Severity.HIGH

    def test_parse_severity_medium(self):
        assert parse_severity("medium") == Severity.MEDIUM
        assert parse_severity("MEDIUM") == Severity.MEDIUM
        assert parse_severity("2") == Severity.MEDIUM

    def test_parse_severity_low(self):
        assert parse_severity("low") == Severity.LOW
        assert parse_severity("LOW") == Severity.LOW
        assert parse_severity("1") == Severity.LOW

    def test_parse_severity_invalid(self):
        with pytest.raises(PatternValidationError):
            parse_severity("invalid")


class TestParseCategory:
    """测试类别解析"""

    def test_parse_category_password(self):
        assert parse_category("password") == Category.PASSWORD

    def test_parse_category_api_key(self):
        assert parse_category("api_key") == Category.API_KEY

    def test_parse_category_token(self):
        assert parse_category("token") == Category.TOKEN

    def test_parse_category_personal_data(self):
        assert parse_category("personal_data") == Category.PERSONAL_DATA

    def test_parse_category_invalid(self):
        with pytest.raises(PatternValidationError):
            parse_category("invalid_category")


class TestParseRegexFlags:
    """测试正则表达式标志解析"""

    def test_parse_flags_ignorecase(self):
        assert parse_regex_flags(["ignorecase"]) == 2  # re.IGNORECASE

    def test_parse_flags_multiline(self):
        assert parse_regex_flags(["multiline"]) == 8  # re.MULTILINE

    def test_parse_flags_multiple(self):
        result = parse_regex_flags(["ignorecase", "multiline"])
        assert result == 10  # re.IGNORECASE | re.MULTILINE

    def test_parse_flags_empty(self):
        assert parse_regex_flags([]) == 0
        assert parse_regex_flags(None) == 0


class TestCreatePatternFromDict:
    """测试从字典创建模式"""

    def test_create_pattern_minimal(self):
        pattern_dict = {
            "name": "test pattern",
            "pattern": r"test\s*=\s*\d+",
            "severity": "high",
            "category": "api_key"
        }
        pattern = create_pattern_from_dict(pattern_dict)
        assert pattern.name == "test pattern"
        assert pattern.severity == Severity.HIGH
        assert pattern.category == Category.API_KEY
        assert pattern.description == "自定义模式: test pattern"

    def test_create_pattern_full(self):
        pattern_dict = {
            "name": "full pattern",
            "pattern": r"secret\s*=\s*\w+",
            "severity": "critical",
            "category": "secret_key",
            "description": "test description",
            "examples": ["secret = 'abc123'"],
            "recommendation": "do not leak",
            "false_positive_rate": "medium",
            "flags": ["ignorecase"]
        }
        pattern = create_pattern_from_dict(pattern_dict)
        assert pattern.name == "full pattern"
        assert pattern.description == "test description"
        assert pattern.examples == ["secret = 'abc123'"]
        assert pattern.recommendation == "do not leak"
        assert pattern.false_positive_rate == "medium"

    def test_create_pattern_missing_required_field(self):
        pattern_dict = {
            "name": "missing fields",
            "pattern": r"test"
        }
        with pytest.raises(PatternValidationError):
            create_pattern_from_dict(pattern_dict)

    def test_create_pattern_invalid_regex(self):
        pattern_dict = {
            "name": "invalid regex",
            "pattern": r"[invalid(regex",
            "severity": "high",
            "category": "password"
        }
        with pytest.raises(PatternValidationError):
            create_pattern_from_dict(pattern_dict)


class TestLoadJsonConfig:
    """测试JSON配置加载"""

    def test_load_valid_json(self):
        config_data = {"patterns": []}
        # Windows requires file to be closed before deleting
        fd, path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)
            config = load_json_config(path)
            assert config == config_data
        finally:
            os.unlink(path)

    def test_load_nonexistent_file(self):
        with pytest.raises(ConfigLoadError):
            load_json_config("/nonexistent/path/config.json")

    def test_load_invalid_json(self):
        fd, path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write("{ invalid json }")
            with pytest.raises(ConfigLoadError):
                load_json_config(path)
        finally:
            os.unlink(path)


class TestLoadPatternsFromConfig:
    """测试从配置加载模式"""

    def test_load_empty_patterns(self):
        config = {"patterns": []}
        patterns = load_patterns_from_config(config)
        assert patterns == []

    def test_load_multiple_patterns(self):
        config = {
            "patterns": [
                {
                    "name": "pattern1",
                    "pattern": r"test1",
                    "severity": "high",
                    "category": "password"
                },
                {
                    "name": "pattern2",
                    "pattern": r"test2",
                    "severity": "low",
                    "category": "api_key"
                }
            ]
        }
        patterns = load_patterns_from_config(config)
        assert len(patterns) == 2
        assert patterns[0].name == "pattern1"
        assert patterns[1].name == "pattern2"

    def test_load_patterns_not_array(self):
        config = {"patterns": "not an array"}
        with pytest.raises(PatternValidationError):
            load_patterns_from_config(config)


class TestLoadCustomPatterns:
    """测试自定义模式加载"""

    def test_load_from_json_file(self):
        config_data = {
            "patterns": [
                {
                    "name": "json test",
                    "pattern": r"json_test\s*=\s*\w+",
                    "severity": "medium",
                    "category": "token"
                }
            ]
        }
        fd, path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)
            patterns = load_custom_patterns(path)
            assert len(patterns) == 1
            assert patterns[0].name == "json test"
        finally:
            os.unlink(path)

    def test_unsupported_format(self):
        fd, path = tempfile.mkstemp(suffix='.txt')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write("test")
            with pytest.raises(ConfigLoadError):
                load_custom_patterns(path)
        finally:
            os.unlink(path)


class TestMergePatterns:
    """测试模式合并"""

    def test_merge_with_none(self):
        result = merge_patterns(None)
        assert result == SENSITIVE_PATTERNS

    def test_merge_append(self):
        import re
        custom = [
            SensitivePattern(
                name="custom",
                category=Category.PASSWORD,
                severity=Severity.HIGH,
                pattern=re.compile(r"custom"),
                description="test",
                examples=["custom = 'test'"]
            )
        ]
        result = merge_patterns(custom)
        assert len(result) == len(SENSITIVE_PATTERNS) + 1
        assert result[-1].name == "custom"

    def test_merge_replace(self):
        import re
        custom = [
            SensitivePattern(
                name="replace",
                category=Category.API_KEY,
                severity=Severity.CRITICAL,
                pattern=re.compile(r"replace"),
                description="test",
                examples=["replace = 'test'"]
            )
        ]
        result = merge_patterns(custom, replace_builtin=True)
        assert len(result) == 1
        assert result[0].name == "replace"


class TestGetAllPatterns:
    """测试获取所有模式"""

    def test_get_without_config(self):
        patterns = get_all_patterns()
        assert patterns == SENSITIVE_PATTERNS

    def test_get_with_config(self):
        config_data = {
            "patterns": [
                {
                    "name": "config pattern",
                    "pattern": r"config_test",
                    "severity": "high",
                    "category": "password"
                }
            ]
        }
        fd, path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)
            patterns = get_all_patterns(path)
            # should include built-in + custom patterns
            assert len(patterns) > len(SENSITIVE_PATTERNS)
            assert any(p.name == "config pattern" for p in patterns)
        finally:
            os.unlink(path)


class TestValidateConfigFile:
    """测试配置文件验证"""

    def test_validate_valid_config(self):
        config_data = {
            "patterns": [
                {
                    "name": "valid pattern",
                    "pattern": r"valid",
                    "severity": "high",
                    "category": "password"
                }
            ]
        }
        fd, path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)
            errors = validate_config_file(path)
            assert errors == []
        finally:
            os.unlink(path)

    def test_validate_invalid_config(self):
        config_data = {
            "patterns": [
                {
                    "name": "missing fields"
                    # missing pattern, severity, category
                }
            ]
        }
        fd, path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(config_data, f)
            errors = validate_config_file(path)
            assert len(errors) > 0
        finally:
            os.unlink(path)

    def test_validate_nonexistent_file(self):
        errors = validate_config_file("/nonexistent/config.json")
        assert len(errors) > 0


class TestPatternDetection:
    """测试自定义模式检测功能"""

    def test_custom_pattern_detects_match(self):
        """测试自定义模式能正确检测匹配"""
        pattern_dict = {
            "name": "test api key",
            "pattern": r"my_api_key\s*=\s*['\"]?\w+['\"]?",
            "severity": "critical",
            "category": "api_key"
        }
        pattern = create_pattern_from_dict(pattern_dict)

        text = 'my_api_key = "secret123"'
        match = pattern.pattern.search(text)
        assert match is not None
        assert "my_api_key" in match.group()

    def test_custom_pattern_with_flags(self):
        """测试带标志的自定义模式"""
        pattern_dict = {
            "name": "case insensitive pattern",
            "pattern": r"API_KEY\s*=\s*\w+",
            "severity": "high",
            "category": "api_key",
            "flags": ["ignorecase"]
        }
        pattern = create_pattern_from_dict(pattern_dict)

        text = 'api_key = secret123'  # lowercase
        match = pattern.pattern.search(text)
        assert match is not None