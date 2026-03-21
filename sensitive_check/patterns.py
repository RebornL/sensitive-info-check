"""敏感信息模式定义

定义各种敏感信息的正则表达式模式。
"""

import re
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import List, Optional, Pattern


class Severity(IntEnum):
    """敏感信息严重级别"""
    CRITICAL = 4    # 高危：密码、密钥、Token等
    HIGH = 3        # 高级：身份证、银行卡等
    MEDIUM = 2      # 中级：手机号、邮箱等
    LOW = 1         # 低级：IP地址等

    @property
    def label(self) -> str:
        """获取显示标签"""
        labels = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "high",
            Severity.MEDIUM: "medium",
            Severity.LOW: "low",
        }
        return labels[self]


class Category(Enum):
    """敏感信息类别"""
    # 认证相关
    PASSWORD = "password"
    API_KEY = "api_key"
    SECRET_KEY = "secret_key"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"

    # 个人信息
    ID_CARD = "id_card"         # 身份证号
    PHONE = "phone"             # 手机号
    EMAIL = "email"             # 邮箱
    BANK_CARD = "bank_card"     # 银行卡号
    PERSONAL_DATA = "personal_data"  # 敏感个人数据

    # 网络信息
    IP_ADDRESS = "ip_address"
    URL_WITH_CRED = "url_with_credentials"

    # 其他
    AWS_KEY = "aws_key"
    DATABASE_URL = "database_url"


@dataclass
class SensitivePattern:
    """敏感信息模式定义"""
    name: str                           # 模式名称
    category: Category                  # 类别
    severity: Severity                  # 严重级别
    pattern: Pattern                    # 正则表达式模式
    description: str                    # 描述
    examples: List[str]                 # 示例
    false_positive_rate: str = "low"    # 误报率估计
    recommendation: str = ""            # 修复建议


# 预定义的敏感信息模式
SENSITIVE_PATTERNS: List[SensitivePattern] = [
    # ============ 认证相关 ============
    SensitivePattern(
        name="密码变量",
        category=Category.PASSWORD,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{4,}['\"]?",
            re.IGNORECASE
        ),
        description="检测到密码变量赋值",
        examples=[
            "password = 'mySecretPass123'",
            "passwd: 'admin123'",
        ],
        recommendation="不要在代码中硬编码密码，应使用环境变量或密钥管理系统"
    ),

    SensitivePattern(
        name="API密钥",
        category=Category.API_KEY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?",
            re.IGNORECASE
        ),
        description="检测到API密钥",
        examples=[
            "api_key = 'sk-1234567890abcdef'",
            "API_KEY: 'AKIAIOSFODNN7EXAMPLE'",
        ],
        recommendation="API密钥应存储在安全配置中，不要硬编码"
    ),

    SensitivePattern(
        name="密钥",
        category=Category.SECRET_KEY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?i)(secret[_-]?key|secretkey|secret)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?",
            re.IGNORECASE
        ),
        description="检测到密钥",
        examples=[
            "secret_key = 'my_super_secret_key_123'",
        ],
        recommendation="密钥应通过安全方式管理，使用密钥管理服务"
    ),

    SensitivePattern(
        name="访问令牌",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?i)(access[_-]?token|auth[_-]?token|bearer[_-]?token|token)\s*[=:]\s*['\"]?[a-zA-Z0-9_\-\.]{20,}['\"]?",
            re.IGNORECASE
        ),
        description="检测到访问令牌",
        examples=[
            "access_token = 'ghp_xxxxxxxxxxxxxxxxxxxx'",
            "authToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'",
        ],
        recommendation="Token应使用安全的存储方式，避免日志打印"
    ),

    SensitivePattern(
        name="私钥",
        category=Category.PRIVATE_KEY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE
        ),
        description="检测到私钥内容",
        examples=[
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ],
        recommendation="私钥文件应妥善保管，禁止出现在代码或日志中"
    ),

    # ============ 云服务密钥 ============
    SensitivePattern(
        name="AWS访问密钥",
        category=Category.AWS_KEY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            re.IGNORECASE
        ),
        description="检测到AWS访问密钥ID",
        examples=[
            "AKIAIOSFODNN7EXAMPLE",
            "ASIAIOSFODNN7EXAMPLE",
        ],
        recommendation="AWS密钥应使用IAM角色或环境变量管理"
    ),

    SensitivePattern(
        name="AWS秘密密钥",
        category=Category.AWS_KEY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[=:]\s*['\"]?[a-zA-Z0-9/+=]{40}['\"]?",
            re.IGNORECASE
        ),
        description="检测到AWS秘密访问密钥",
        examples=[
            "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
        ],
        recommendation="AWS秘密密钥应通过安全渠道管理"
    ),

    # ============ 个人信息 ============
    SensitivePattern(
        name="中国身份证号",
        category=Category.ID_CARD,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"
        ),
        description="检测到中国身份证号",
        examples=[
            "11010519900307234X",
            "440308199901014512",
        ],
        recommendation="身份证号属于个人隐私，不应出现在日志中"
    ),

    SensitivePattern(
        name="中国手机号",
        category=Category.PHONE,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"\b1[3-9]\d{9}\b"
        ),
        description="检测到中国手机号",
        examples=[
            "13812345678",
            "18900001111",
        ],
        recommendation="手机号属于个人隐私，日志中应脱敏处理"
    ),

    SensitivePattern(
        name="电子邮箱",
        category=Category.EMAIL,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        ),
        description="检测到电子邮箱地址",
        examples=[
            "user@example.com",
            "test.user@domain.org",
        ],
        recommendation="邮箱地址属于个人隐私，应脱敏后记录"
    ),

    SensitivePattern(
        name="银行卡号",
        category=Category.BANK_CARD,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(?:62|4|5)\d{14,17}\b"
        ),
        description="检测到银行卡号",
        examples=[
            "6222021234567890123",
            "4111111111111111",
        ],
        recommendation="银行卡号属于金融敏感信息，严禁日志打印"
    ),

    # ============ 敏感个人数据 ============
    SensitivePattern(
        name="护照号码",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b[DEGS][A-Z]\d{7}|[A-Z]{2}\d{7}\b"
        ),
        description="检测到护照号码",
        examples=[
            "D12345678",
            "EJ1234567",
            "G12345678",
        ],
        recommendation="护照号码属于敏感个人数据，应脱敏后记录"
    ),

    SensitivePattern(
        name="驾驶证号",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b[1-9]\d{10}[A-Z0-9]{2}\d{2}\b"
        ),
        description="检测到驾驶证号",
        examples=[
            "110105199003070512",
        ],
        recommendation="驾驶证号属于敏感个人数据，应脱敏处理"
    ),

    SensitivePattern(
        name="社会保障号",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(?:SSN|社保号|社会保障号|社保账号)[：:]*\s*[A-Z]?\d{9,12}\b",
            re.IGNORECASE
        ),
        description="检测到社会保障号",
        examples=[
            "SSN: 123456789",
            "社保号：123456789012",
        ],
        recommendation="社会保障号属于敏感个人数据，严禁日志打印"
    ),

    SensitivePattern(
        name="医保卡号",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(?:医保卡|医保号|医疗保险号)[：:]*\s*\d{10,18}\b",
            re.IGNORECASE
        ),
        description="检测到医保卡号",
        examples=[
            "医保卡号：1234567890123456",
        ],
        recommendation="医保卡号属于敏感个人数据，应脱敏处理"
    ),

    SensitivePattern(
        name="统一社会信用代码",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"\b[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}\b"
        ),
        description="检测到统一社会信用代码（企业身份证）",
        examples=[
            "91110000600007336F",
            "91320106MA1MRHHN8X",
        ],
        recommendation="统一社会信用代码属于企业敏感信息，应谨慎处理"
    ),

    SensitivePattern(
        name="姓名变量",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(user[_-]?name|real[_-]?name|full[_-]?name|customer[_-]?name|person[_-]?name|username)\s*[=:]\s*['\"][\u4e00-\u9fa5]{2,4}['\"]",
            re.IGNORECASE
        ),
        description="检测到姓名变量赋值（中文姓名）",
        examples=[
            "user_name = '张三'",
            "realName: '李四五'",
        ],
        recommendation="姓名属于个人隐私信息，日志中应脱敏处理"
    ),

    SensitivePattern(
        name="地址信息",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(address|addr|home[_-]?address|live[_-]?address|residence[_-]?address|居住地址|家庭住址|详细地址)[：:]*\s*['\"]?[\u4e00-\u9fa5]{2,}(省|市|区|县|路|街|道|号|栋|单元|室|楼)['\"]?",
            re.IGNORECASE
        ),
        description="检测到地址信息",
        examples=[
            "address = '广东省深圳市南山区科技园路100号'",
            "home_address: '北京市朝阳区建国门外大街1号'",
        ],
        recommendation="地址信息属于个人隐私，日志中应脱敏处理"
    ),

    SensitivePattern(
        name="港澳通行证号",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b[CW]\d{8}\b"
        ),
        description="检测到港澳通行证号",
        examples=[
            "C12345678",
            "W12345678",
        ],
        recommendation="港澳通行证号属于敏感证件信息，应脱敏处理"
    ),

    SensitivePattern(
        name="台湾通行证号",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\bT\d{8}\b"
        ),
        description="检测到台湾通行证号",
        examples=[
            "T12345678",
        ],
        recommendation="台湾通行证号属于敏感证件信息，应脱敏处理"
    ),

    SensitivePattern(
        name="军官证号",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(?:军字第|军证第|军官证)[：:]*\s*[A-Z]?\d{6,8}\b",
            re.IGNORECASE
        ),
        description="检测到军官证号",
        examples=[
            "军字第123456号",
            "军官证：A123456",
        ],
        recommendation="军官证号属于敏感证件信息，应脱敏处理"
    ),

    SensitivePattern(
        name="学籍号",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"\b(?:学籍号|学号)[：:]*\s*[A-Z]?\d{10,20}\b",
            re.IGNORECASE
        ),
        description="检测到学籍号",
        examples=[
            "学籍号：G123456789012",
            "学号：202012345678",
        ],
        recommendation="学籍号属于学生隐私信息，应脱敏处理"
    ),

    # ============ 运动健康类数据 ============
    SensitivePattern(
        name="心率数据",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(heart[_-]?rate|心率|心跳)[：:]*\s*\d{2,3}\s*(bpm|次/分|次每分)?",
            re.IGNORECASE
        ),
        description="检测到心率数据",
        examples=[
            "heart_rate: 72bpm",
            "心率：120次/分",
        ],
        recommendation="心率数据属于健康隐私信息，日志中应脱敏处理"
    ),

    SensitivePattern(
        name="血压数据",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(blood[_-]?pressure|血压|收缩压|舒张压)[：:]*\s*\d{2,3}\s*[/-]\s*\d{2,3}\s*(mmHg|mmhg)?",
            re.IGNORECASE
        ),
        description="检测到血压数据",
        examples=[
            "blood_pressure: 120/80mmHg",
            "血压：140/90",
        ],
        recommendation="血压数据属于健康隐私信息，日志中应脱敏处理"
    ),

    SensitivePattern(
        name="血糖数据",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(blood[_-]?sugar|blood[_-]?glucose|血糖|空腹血糖|餐后血糖)[：:]*\s*\d{1,2}\.?\d*\s*(mmol/L|mg/dL)?",
            re.IGNORECASE
        ),
        description="检测到血糖数据",
        examples=[
            "blood_sugar: 5.6mmol/L",
            "血糖：7.2",
        ],
        recommendation="血糖数据属于健康隐私信息，日志中应脱敏处理"
    ),

    SensitivePattern(
        name="体重BMI数据",
        category=Category.PERSONAL_DATA,
        severity=Severity.LOW,
        pattern=re.compile(
            r"(?i)(weight|body[_-]?weight|体重|body[_-]?mass[_-]?index|BMI|身体质量指数)[：:]*\s*\d{2,3}\.?\d*\s*(kg|kg/m2)?",
            re.IGNORECASE
        ),
        description="检测到体重/BMI数据",
        examples=[
            "weight: 65.5kg",
            "BMI: 22.5",
        ],
        recommendation="体重/BMI数据属于个人隐私，可根据需求决定是否脱敏"
    ),

    SensitivePattern(
        name="步数数据",
        category=Category.PERSONAL_DATA,
        severity=Severity.LOW,
        pattern=re.compile(
            r"(?i)(step[_-]?count|steps|步数|今日步数|运动步数)[：:]*\s*\d{3,6}\s*(步)?",
            re.IGNORECASE
        ),
        description="检测到步数数据",
        examples=[
            "step_count: 8500步",
            "steps: 10234",
        ],
        recommendation="步数数据属于运动隐私，可根据需求决定是否脱敏"
    ),

    SensitivePattern(
        name="睡眠数据",
        category=Category.PERSONAL_DATA,
        severity=Severity.LOW,
        pattern=re.compile(
            r"(?i)(sleep[_-]?duration|sleep[_-]?time|睡眠时长|睡眠时间|深度睡眠)[：:]*\s*\d{1,2}\.?\d*\s*(小时|h|hour)?",
            re.IGNORECASE
        ),
        description="检测到睡眠数据",
        examples=[
            "sleep_duration: 7.5小时",
            "深度睡眠：2.3h",
        ],
        recommendation="睡眠数据属于个人隐私，可根据需求决定是否脱敏"
    ),

    SensitivePattern(
        name="GPS位置轨迹",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?i)(gps|location|latitude|longitude|经度|纬度|位置坐标|当前位置)[：:]*\s*(-?\d{2,3}\.\d{4,})\s*,\s*(-?\d{2,3}\.\d{4,})",
            re.IGNORECASE
        ),
        description="检测到GPS位置/轨迹数据",
        examples=[
            "location: 39.9042, 116.4074",
            "GPS: 31.2304, 121.4737",
        ],
        recommendation="GPS位置轨迹属于敏感位置隐私，严禁日志打印"
    ),

    SensitivePattern(
        name="健康档案数据",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?i)(health[_-]?record|medical[_-]?record|病历号|健康档案|就诊记录|体检报告|门诊号|住院号)[：:]*\s*[A-Z]?\d{6,20}",
            re.IGNORECASE
        ),
        description="检测到健康档案/病历数据",
        examples=[
            "health_record: MR202312001",
            "病历号：BL12345678",
        ],
        recommendation="健康档案/病历数据属于医疗隐私，严禁日志打印"
    ),

    SensitivePattern(
        name="血型数据",
        category=Category.PERSONAL_DATA,
        severity=Severity.LOW,
        pattern=re.compile(
            r"(?i)(blood[_-]?type|血型)[：:]*\s*(A|B|AB|O)[型]?",
            re.IGNORECASE
        ),
        description="检测到血型数据",
        examples=[
            "blood_type: A",
            "血型：AB型",
        ],
        recommendation="血型数据属于个人隐私，可根据需求决定是否脱敏"
    ),

    # ============ 设备类型数据 ============
    SensitivePattern(
        name="IMEI号",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?i)(imei|设备IMEI|手机串号)[：:]*\s*\d{15}",
            re.IGNORECASE
        ),
        description="检测到IMEI设备标识",
        examples=[
            "imei: 359881060123456",
            "IMEI：861234567890123",
        ],
        recommendation="IMEI属于设备唯一标识，属于隐私信息，应脱敏处理"
    ),

    SensitivePattern(
        name="IMSI号",
        category=Category.PERSONAL_DATA,
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?i)(imsi|国际移动用户识别码)[：:]*\s*\d{15}",
            re.IGNORECASE
        ),
        description="检测到IMSI用户识别码",
        examples=[
            "imsi: 460001234567890",
        ],
        recommendation="IMSI属于用户识别码，属于敏感隐私，严禁日志打印"
    ),

    SensitivePattern(
        name="MAC地址",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(mac[_-]?address|mac地址|物理地址)[：:]*\s*([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
            re.IGNORECASE
        ),
        description="检测到MAC地址",
        examples=[
            "mac_address: 00:1A:2B:3C:4D:5E",
            "MAC：A1-B2-C3-D4-E5-F6",
        ],
        recommendation="MAC地址属于设备标识，应脱敏处理"
    ),

    SensitivePattern(
        name="设备序列号",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(serial[_-]?number|device[_-]?serial|设备序列号|序列号|SN)[：:]*\s*[A-Z0-9]{8,20}",
            re.IGNORECASE
        ),
        description="检测到设备序列号",
        examples=[
            "serial_number: C02XG0FDHV2Q",
            "SN：5CD12345ABC",
        ],
        recommendation="设备序列号属于设备标识，应脱敏处理"
    ),

    SensitivePattern(
        name="设备UUID",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(device[_-]?uuid|device[_-]?id|设备UUID|设备ID|uuid)[：:]*\s*[0-9a-fA-F]{8}[-]?[0-9a-fA-F]{4}[-]?[0-9a-fA-F]{4}[-]?[0-9a-fA-F]{4}[-]?[0-9a-fA-F]{12}",
            re.IGNORECASE
        ),
        description="检测到设备UUID/唯一标识",
        examples=[
            "device_uuid: 550e8400-e29b-41d4-a716-446655440000",
            "uuid: 123e4567e89b12d3a456426614174000",
        ],
        recommendation="设备UUID属于设备唯一标识，应脱敏处理"
    ),

    SensitivePattern(
        name="Android ID",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(android[_-]?id)[：:]*\s*[0-9a-fA-F]{16}",
            re.IGNORECASE
        ),
        description="检测到Android ID",
        examples=[
            "android_id: 9774d56d682e549c",
        ],
        recommendation="Android ID属于设备标识，应脱敏处理"
    ),

    SensitivePattern(
        name="IDFA/IDFV",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(idfa|idf[av]|identifier[_-]?for[_-]?vendor|广告标识符)[：:]*\s*[0-9A-Fa-f]{8}[-]?[0-9A-Fa-f]{4}[-]?[0-9A-Fa-f]{4}[-]?[0-9A-Fa-f]{4}[-]?[0-9A-Fa-f]{12}",
            re.IGNORECASE
        ),
        description="检测到iOS广告标识符IDFA/IDFV",
        examples=[
            "idfa: 4D6B9C3E-1A2B-4C3D-8E9F-0A1B2C3D4E5F",
            "IDFV：12345678-1234-1234-1234-123456789ABC",
        ],
        recommendation="IDFA/IDFV属于设备广告标识，应脱敏处理"
    ),

    SensitivePattern(
        name="OAID",
        category=Category.PERSONAL_DATA,
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)(oaid|匿名设备标识符)[：:]*\s*[0-9A-Fa-f]{16,32}",
            re.IGNORECASE
        ),
        description="检测到OAID匿名设备标识符",
        examples=[
            "oaid: 1a2b3c4d5e6f7a8b",
        ],
        recommendation="OAID属于设备广告标识，应脱敏处理"
    ),

    # ============ 网络信息 ============
    SensitivePattern(
        name="IP地址",
        category=Category.IP_ADDRESS,
        severity=Severity.LOW,
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        description="检测到IP地址",
        examples=[
            "192.168.1.100",
            "10.0.0.1",
        ],
        recommendation="内网IP地址可根据需求决定是否脱敏，公网IP建议脱敏"
    ),

    SensitivePattern(
        name="带凭据的URL",
        category=Category.URL_WITH_CRED,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?i)(?:mysql|postgres|mongodb|redis|http|https|ftp)://[^:]+:[^@]+@[^\s'\"]+"
        ),
        description="检测到包含凭据的URL",
        examples=[
            "mysql://user:password@localhost:3306/db",
            "redis://:secret123@127.0.0.1:6379",
        ],
        recommendation="URL中的凭据应移除或使用环境变量"
    ),

    SensitivePattern(
        name="数据库连接串",
        category=Category.DATABASE_URL,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?i)(?:jdbc:|database[_-]?url|db[_-]?url)\s*[=:]\s*['\"]?[^\s'\"]+['\"]?"
        ),
        description="检测到数据库连接串",
        examples=[
            "jdbc:mysql://localhost:3306/mydb?user=root&password=123456",
            "database_url = 'postgresql://user:pass@localhost/db'",
        ],
        recommendation="数据库连接串中的凭据应使用安全配置管理"
    ),
]


def get_patterns_by_severity(severity: Severity) -> List[SensitivePattern]:
    """获取指定严重级别的模式"""
    return [p for p in SENSITIVE_PATTERNS if p.severity == severity]


def get_patterns_by_category(category: Category) -> List[SensitivePattern]:
    """获取指定类别的模式"""
    return [p for p in SENSITIVE_PATTERNS if p.category == category]


def get_patterns_by_severities(severities: List[Severity]) -> List[SensitivePattern]:
    """获取多个严重级别的模式"""
    return [p for p in SENSITIVE_PATTERNS if p.severity in severities]