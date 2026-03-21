"""测试敏感信息模式"""

import pytest
from sensitive_check.patterns import (
    SENSITIVE_PATTERNS,
    Severity,
    Category,
    get_patterns_by_severity,
    get_patterns_by_category,
    get_patterns_by_severities,
)


class TestPatterns:
    """测试敏感信息模式"""

    def test_patterns_exist(self):
        """测试模式存在"""
        assert len(SENSITIVE_PATTERNS) > 0

    def test_password_detection(self):
        """测试密码检测"""
        test_cases = [
            "password = 'mySecretPass123'",
            "passwd: 'admin123'",
            "pwd = 'test1234'",
        ]
        pattern = next((p for p in SENSITIVE_PATTERNS if p.category == Category.PASSWORD), None)
        assert pattern is not None

        for case in test_cases:
            match = pattern.pattern.search(case)
            assert match is not None, f"Failed to match: {case}"

    def test_api_key_detection(self):
        """测试API密钥检测"""
        test_cases = [
            "api_key = 'sk-1234567890abcdef'",
            "API_KEY: 'AKIAIOSFODNN7EXAMPLE'",
        ]
        pattern = next((p for p in SENSITIVE_PATTERNS if p.category == Category.API_KEY), None)
        assert pattern is not None

        for case in test_cases:
            match = pattern.pattern.search(case)
            assert match is not None, f"Failed to match: {case}"

    def test_id_card_detection(self):
        """测试身份证号检测"""
        test_cases = [
            "ID card: 11010519900307234X",
            "idcard 440308199901014512",
        ]
        pattern = next((p for p in SENSITIVE_PATTERNS if p.category == Category.ID_CARD), None)
        assert pattern is not None

        for case in test_cases:
            match = pattern.pattern.search(case)
            assert match is not None, f"Failed to match: {case}"

    def test_phone_detection(self):
        """测试手机号检测"""
        test_cases = [
            "phone: 13812345678",
            "mobile 18900001111",
        ]
        pattern = next((p for p in SENSITIVE_PATTERNS if p.category == Category.PHONE), None)
        assert pattern is not None

        for case in test_cases:
            match = pattern.pattern.search(case)
            assert match is not None, f"Failed to match: {case}"

    def test_email_detection(self):
        """测试邮箱检测"""
        test_cases = [
            "email: user@example.com",
            "mail test.user@domain.org",
        ]
        pattern = next((p for p in SENSITIVE_PATTERNS if p.category == Category.EMAIL), None)
        assert pattern is not None

        for case in test_cases:
            match = pattern.pattern.search(case)
            assert match is not None, f"Failed to match: {case}"

    def test_aws_key_detection(self):
        """测试AWS密钥检测"""
        test_cases = [
            "AKIAIOSFODNN7EXAMPLE",
            "ASIAIOSFODNN7EXAMPLE",
        ]
        pattern = next((p for p in SENSITIVE_PATTERNS if p.category == Category.AWS_KEY), None)
        assert pattern is not None

        for case in test_cases:
            match = pattern.pattern.search(case)
            assert match is not None, f"Failed to match: {case}"

    def test_url_with_credentials(self):
        """测试带凭据的URL检测"""
        test_cases = [
            "mysql://user:password@localhost:3306/db",
        ]
        pattern = next((p for p in SENSITIVE_PATTERNS if p.category == Category.URL_WITH_CRED), None)
        assert pattern is not None

        for case in test_cases:
            match = pattern.pattern.search(case)
            assert match is not None, f"Failed to match: {case}"

    def test_get_patterns_by_severity(self):
        """测试按严重级别获取模式"""
        critical_patterns = get_patterns_by_severity(Severity.CRITICAL)
        assert len(critical_patterns) > 0
        for p in critical_patterns:
            assert p.severity == Severity.CRITICAL

    def test_get_patterns_by_category(self):
        """测试按类别获取模式"""
        password_patterns = get_patterns_by_category(Category.PASSWORD)
        assert len(password_patterns) > 0
        for p in password_patterns:
            assert p.category == Category.PASSWORD

    def test_get_patterns_by_severities(self):
        """测试按多个严重级别获取模式"""
        patterns = get_patterns_by_severities([Severity.CRITICAL, Severity.HIGH])
        assert len(patterns) > 0
        for p in patterns:
            assert p.severity in [Severity.CRITICAL, Severity.HIGH]

    def test_passport_detection(self):
        """测试护照号码检测"""
        test_cases = [
            "passport: DE1234567",
            "passport_number EJ1234567",
        ]
        pattern = next((p for p in SENSITIVE_PATTERNS if p.category == Category.PERSONAL_DATA and "护照" in p.name), None)
        assert pattern is not None

        for case in test_cases:
            match = pattern.pattern.search(case)
            assert match is not None, f"Failed to match: {case}"

    def test_personal_data_category_exists(self):
        """测试敏感个人数据类别存在"""
        personal_patterns = get_patterns_by_category(Category.PERSONAL_DATA)
        assert len(personal_patterns) > 0, "敏感个人数据模式应该存在"