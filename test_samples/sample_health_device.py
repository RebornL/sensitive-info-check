# 测试样例 - 运动健康类数据 & 设备类型数据
# 此文件包含敏感健康数据和设备数据打印示例

import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# ============ 运动健康类数据 ============
def log_heart_rate():
    """心率数据"""
    # 危险：打印心率
    print("heart_rate: 72bpm")
    logging.info("心率：120次/分")


def log_blood_pressure():
    """血压数据"""
    # 危险：打印血压
    print("blood_pressure: 120/80mmHg")
    logging.info("血压：140/90")


def log_blood_sugar():
    """血糖数据"""
    # 危险：打印血糖
    print("blood_sugar: 5.6mmol/L")
    logging.info("血糖：7.2")


def log_weight_bmi():
    """体重/BMI数据"""
    # 危险：打印体重和BMI
    print("weight: 65.5kg")
    logging.info("BMI: 22.5")


def log_steps():
    """步数数据"""
    # 危险：打印步数
    print("step_count: 8500步")
    logging.info("steps: 10234")


def log_sleep():
    """睡眠数据"""
    # 危险：打印睡眠数据
    print("sleep_duration: 7.5小时")
    logging.info("深度睡眠：2.3h")


def log_gps_location():
    """GPS位置轨迹"""
    # 危险：打印GPS坐标（严重）
    print("location: 39.9042, 116.4074")
    logging.info("GPS: 31.2304, 121.4737")
    logger.debug("latitude: 22.5431, longitude: 114.0579")


def log_health_record():
    """健康档案数据"""
    # 危险：打印病历号等
    print("health_record: MR202312001")
    logging.info("病历号：BL12345678")
    logger.debug("住院号：ZY20240001")


def log_blood_type():
    """血型数据"""
    # 危险：打印血型
    print("blood_type: A")
    logging.info("血型：AB型")


# ============ 设备类型数据 ============
def log_imei():
    """IMEI号"""
    # 危险：打印IMEI
    print("imei: 359881060123456")
    logging.info("IMEI：861234567890123")


def log_imsi():
    """IMSI号"""
    # 危险：打印IMSI（严重）
    print("imsi: 460001234567890")


def log_mac_address():
    """MAC地址"""
    # 危险：打印MAC地址
    print("mac_address: 00:1A:2B:3C:4D:5E")
    logging.info("MAC：A1-B2-C3-D4-E5-F6")


def log_device_serial():
    """设备序列号"""
    # 危险：打印序列号
    print("serial_number: C02XG0FDHV2Q")
    logging.info("SN：5CD12345ABC")


def log_device_uuid():
    """设备UUID"""
    # 危险：打印设备UUID
    print("device_uuid: 550e8400-e29b-41d4-a716-446655440000")
    logging.info("uuid: 123e4567e89b12d3a456426614174000")


def log_android_id():
    """Android ID"""
    # 危险：打印Android ID
    print("android_id: 9774d56d682e549c")


def log_idfa():
    """IDFA/IDFV"""
    # 危险：打印iOS广告标识符
    print("idfa: 4D6B9C3E-1A2B-4C3D-8E9F-0A1B2C3D4E5F")
    logging.info("IDFV：12345678-1234-1234-1234-123456789ABC")


def log_oaid():
    """OAID"""
    # 危险：打印OAID
    print("oaid: 1a2b3c4d5e6f7a8b")


def normal_logging():
    """正常日志（无敏感信息）"""
    # 安全：没有敏感信息
    user_count = 100
    logging.info(f"Total users: {user_count}")
    print("Processing completed")
    logger.debug("System running normally")