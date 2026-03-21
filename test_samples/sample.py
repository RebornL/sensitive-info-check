# 测试样例 - Python
# 此文件包含一些敏感日志打印示例，用于测试工具

import logging

# 配置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def process_user_login(username, password):
    """处理用户登录"""
    # 危险：打印密码
    print(f"User login: {username}, password: {password}")

    # 危险：日志记录密码
    logging.info(f"Login attempt with password: {password}")

    # 危险：logger打印密码
    logger.debug(f"Password received: {password}")


def connect_database():
    """连接数据库"""
    # 危险：数据库连接串包含密码
    db_url = "mysql://admin:password123@localhost:3306/mydb"
    print(f"Connecting to: {db_url}")

    # 危险：API密钥
    api_key = "sk-1234567890abcdefghijklmnop"
    logging.info(f"Using API key: {api_key}")


def process_payment():
    """处理支付"""
    # 危险：银行卡号
    bank_card = "6222021234567890123"
    print(f"Processing card: {bank_card}")

    # 危险：身份证号
    id_card = "11010519900307234X"
    logging.debug(f"User ID card: {id_card}")

    # 危险：手机号
    phone = "13812345678"
    logger.info(f"User phone: {phone}")


def aws_operations():
    """AWS操作"""
    # 危险：AWS密钥
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    logging.info(f"AWS Key: {aws_access_key}")
    print(f"AWS Secret: {aws_secret}")


def normal_logging():
    """正常日志（无敏感信息）"""
    # 安全：没有敏感信息
    user_count = 100
    logging.info(f"Total users: {user_count}")
    print("Application started successfully")
    logger.debug("Processing request...")


# 私钥示例
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MfWb/yy7k0A0
...（省略中间内容）...
-----END RSA PRIVATE KEY-----"""

# 直接打印私钥（极度危险）
print(f"Private key: {PRIVATE_KEY}")