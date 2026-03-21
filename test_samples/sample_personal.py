# 测试样例 - 敏感个人数据
# 此文件包含敏感个人数据打印示例，用于测试工具

import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def process_user_profile():
    """处理用户档案"""
    # 危险：直接打印护照号
    print("User passport: DE1234567")
    logging.info("HK Pass: C12345678")
    logger.debug("TW Pass: T12345678")


def process_employee():
    """处理员工信息"""
    # 危险：打印军官证
    print("Military ID: 军字第123456号")
    logging.info("Driver license: 110105199003070512")


def process_social_security():
    """处理社保信息"""
    # 危险：打印社保号
    print("Social security SSN: 123456789")
    logging.info("Medical card 医保卡号：1234567890123456")


def process_student():
    """处理学生信息"""
    # 危险：打印学籍号
    print("Student ID 学籍号：G123456789012")


def process_company():
    """处理企业信息"""
    # 危险：打印统一社会信用代码
    print("Company credit code: 91110000600007336F")


def process_user_address():
    """处理用户地址"""
    # 危险：打印详细地址
    print("User address: 广东省深圳市南山区科技园路100号")

    # 危险：打印姓名
    logging.info("User real_name: 张三")


def normal_logging():
    """正常日志（无敏感信息）"""
    # 安全：没有敏感信息
    user_count = 100
    logging.info(f"Total users: {user_count}")
    print("Processing completed")