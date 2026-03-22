"""配置文件加载器

支持从JSON配置文件加载自定义敏感信息检测规则。
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .patterns import (
    Category,
    SensitivePattern,
    Severity,
    SENSITIVE_PATTERNS,
)


class ConfigLoadError(Exception):
    """配置加载错误"""
    pass


class PatternValidationError(Exception):
    """模式验证错误"""
    pass


# 严重级别字符串映射
SEVERITY_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "4": Severity.CRITICAL,
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
}

# 类别字符串映射
CATEGORY_MAP: Dict[str, Category] = {
    "password": Category.PASSWORD,
    "api_key": Category.API_KEY,
    "secret_key": Category.SECRET_KEY,
    "token": Category.TOKEN,
    "private_key": Category.PRIVATE_KEY,
    "id_card": Category.ID_CARD,
    "phone": Category.PHONE,
    "email": Category.EMAIL,
    "bank_card": Category.BANK_CARD,
    "personal_data": Category.PERSONAL_DATA,
    "ip_address": Category.IP_ADDRESS,
    "url_with_credentials": Category.URL_WITH_CRED,
    "aws_key": Category.AWS_KEY,
    "database_url": Category.DATABASE_URL,
}


def parse_severity(severity_str: str) -> Severity:
    """解析严重级别字符串

    Args:
        severity_str: 严重级别字符串，如 "critical", "high", "medium", "low"

    Returns:
        Severity枚举值

    Raises:
        PatternValidationError: 无效的严重级别
    """
    severity_lower = severity_str.lower().strip()
    if severity_lower not in SEVERITY_MAP:
        valid_values = ", ".join(SEVERITY_MAP.keys())
        raise PatternValidationError(
            f"无效的严重级别 '{severity_str}'，有效值: {valid_values}"
        )
    return SEVERITY_MAP[severity_lower]


def parse_category(category_str: str) -> Category:
    """解析类别字符串

    Args:
        category_str: 类别字符串，如 "password", "api_key"

    Returns:
        Category枚举值

    Raises:
        PatternValidationError: 无效的类别
    """
    category_lower = category_str.lower().strip()
    if category_lower not in CATEGORY_MAP:
        valid_values = ", ".join(CATEGORY_MAP.keys())
        raise PatternValidationError(
            f"无效的类别 '{category_str}'，有效值: {valid_values}"
        )
    return CATEGORY_MAP[category_lower]


def parse_regex_flags(flags_list: Optional[List[str]]) -> int:
    """解析正则表达式标志

    Args:
        flags_list: 标志列表，如 ["IGNORECASE", "MULTILINE"]

    Returns:
        组合后的标志值
    """
    if not flags_list:
        return 0

    flag_map = {
        "ignorecase": re.IGNORECASE,
        "i": re.IGNORECASE,
        "multiline": re.MULTILINE,
        "m": re.MULTILINE,
        "dotall": re.DOTALL,
        "s": re.DOTALL,
        "verbose": re.VERBOSE,
        "x": re.VERBOSE,
        "ascii": re.ASCII,
        "a": re.ASCII,
    }

    result = 0
    for flag_str in flags_list:
        flag_lower = flag_str.lower()
        if flag_lower in flag_map:
            result |= flag_map[flag_lower]

    return result


def validate_pattern_dict(pattern_dict: Dict[str, Any], index: int) -> None:
    """验证模式字典的必需字段

    Args:
        pattern_dict: 模式配置字典
        index: 模式索引（用于错误信息）

    Raises:
        PatternValidationError: 验证失败
    """
    required_fields = ["name", "pattern", "severity", "category"]
    missing_fields = [f for f in required_fields if f not in pattern_dict]

    if missing_fields:
        raise PatternValidationError(
            f"模式 #{index + 1} 缺少必需字段: {', '.join(missing_fields)}"
        )


def create_pattern_from_dict(pattern_dict: Dict[str, Any], index: int = 0) -> SensitivePattern:
    """从字典创建SensitivePattern对象

    Args:
        pattern_dict: 模式配置字典
        index: 模式索引（用于错误信息）

    Returns:
        SensitivePattern对象

    Raises:
        PatternValidationError: 配置验证失败
    """
    # 验证必需字段
    validate_pattern_dict(pattern_dict, index)

    try:
        # 解析严重级别
        severity = parse_severity(str(pattern_dict["severity"]))

        # 解析类别
        category = parse_category(str(pattern_dict["category"]))

        # 编译正则表达式
        pattern_str = pattern_dict["pattern"]
        flags = parse_regex_flags(pattern_dict.get("flags", []))

        try:
            compiled_pattern = re.compile(pattern_str, flags)
        except re.error as e:
            raise PatternValidationError(
                f"模式 #{index + 1} '{pattern_dict['name']}' 正则表达式错误: {e}"
            )

        # 创建SensitivePattern对象
        return SensitivePattern(
            name=pattern_dict["name"],
            category=category,
            severity=severity,
            pattern=compiled_pattern,
            description=pattern_dict.get("description", f"自定义模式: {pattern_dict['name']}"),
            examples=pattern_dict.get("examples", []),
            false_positive_rate=pattern_dict.get("false_positive_rate", "low"),
            recommendation=pattern_dict.get("recommendation", ""),
        )

    except PatternValidationError:
        raise
    except Exception as e:
        raise PatternValidationError(
            f"模式 #{index + 1} 配置解析失败: {e}"
        )


def load_json_config(config_path: Union[str, Path]) -> Dict[str, Any]:
    """加载JSON配置文件

    Args:
        config_path: 配置文件路径

    Returns:
        配置字典

    Raises:
        ConfigLoadError: 配置文件加载失败
    """
    config_path = Path(config_path)

    if not config_path.exists():
        raise ConfigLoadError(f"配置文件不存在: {config_path}")

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigLoadError(f"JSON解析错误: {e}")
    except Exception as e:
        raise ConfigLoadError(f"读取配置文件失败: {e}")


def load_patterns_from_config(config: Dict[str, Any]) -> List[SensitivePattern]:
    """从配置字典加载自定义模式

    Args:
        config: 配置字典

    Returns:
        自定义模式列表

    Raises:
        PatternValidationError: 模式验证失败
    """
    patterns = config.get("patterns", [])

    if not isinstance(patterns, list):
        raise PatternValidationError("'patterns' 必须是数组")

    custom_patterns: List[SensitivePattern] = []

    for i, pattern_dict in enumerate(patterns):
        if not isinstance(pattern_dict, dict):
            raise PatternValidationError(f"模式 #{i + 1} 必须是对象")

        pattern = create_pattern_from_dict(pattern_dict, i)
        custom_patterns.append(pattern)

    return custom_patterns


def load_custom_patterns(config_path: Union[str, Path]) -> List[SensitivePattern]:
    """从配置文件加载自定义模式

    Args:
        config_path: 配置文件路径（支持.json格式）

    Returns:
        自定义模式列表

    Raises:
        ConfigLoadError: 配置文件加载失败
        PatternValidationError: 模式验证失败
    """
    config_path = Path(config_path)
    suffix = config_path.suffix.lower()

    if suffix == '.json':
        config = load_json_config(config_path)
    else:
        raise ConfigLoadError(
            f"不支持的配置文件格式: {suffix}，仅支持 .json"
        )

    return load_patterns_from_config(config)


def merge_patterns(
    custom_patterns: Optional[List[SensitivePattern]] = None,
    replace_builtin: bool = False
) -> List[SensitivePattern]:
    """合并内置模式和自定义模式

    Args:
        custom_patterns: 自定义模式列表
        replace_builtin: 是否替换内置模式（默认为False，即追加）

    Returns:
        合并后的模式列表
    """
    if custom_patterns is None:
        return SENSITIVE_PATTERNS.copy()

    if replace_builtin:
        return custom_patterns.copy()

    # 合并模式（自定义模式追加到内置模式后面）
    return SENSITIVE_PATTERNS + custom_patterns


def get_all_patterns(
    config_path: Optional[Union[str, Path]] = None,
    replace_builtin: bool = False
) -> List[SensitivePattern]:
    """获取所有检测模式（内置 + 自定义）

    Args:
        config_path: 自定义配置文件路径
        replace_builtin: 是否替换内置模式

    Returns:
        模式列表

    Raises:
        ConfigLoadError: 配置文件加载失败
        PatternValidationError: 模式验证失败
    """
    if config_path is None:
        return SENSITIVE_PATTERNS.copy()

    custom_patterns = load_custom_patterns(config_path)
    return merge_patterns(custom_patterns, replace_builtin)


def validate_config_file(config_path: Union[str, Path]) -> List[str]:
    """验证配置文件并返回错误信息列表

    Args:
        config_path: 配置文件路径

    Returns:
        错误信息列表（空列表表示验证通过）
    """
    errors: List[str] = []

    try:
        config = load_json_config(config_path)
        patterns = config.get("patterns", [])

        for i, pattern_dict in enumerate(patterns):
            try:
                validate_pattern_dict(pattern_dict, i)
                create_pattern_from_dict(pattern_dict, i)
            except PatternValidationError as e:
                errors.append(str(e))

    except ConfigLoadError as e:
        errors.append(str(e))
    except Exception as e:
        errors.append(f"未知错误: {e}")

    return errors