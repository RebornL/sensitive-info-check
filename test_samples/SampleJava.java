// 测试样例 - Java
// 此文件包含一些敏感日志打印示例

import java.util.logging.Logger;
import org.slf4j.LoggerFactory;

public class UserService {
    private static final Logger logger = Logger.getLogger(UserService.class.getName());
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(UserService.class);

    // 危险：硬编码密码
    private String dbPassword = "admin123";

    public void login(String username, String password) {
        // 危险：使用System.out打印密码
        System.out.println("User login: " + username + ", password: " + password);

        // 危险：使用logger打印密码
        logger.info("Login attempt with password: " + password);

        // 危险：使用SLF4J打印密码
        log.debug("Password received: {}", password);
    }

    public void connectDatabase() {
        // 危险：数据库连接串包含密码
        String dbUrl = "mysql://admin:password123@localhost:3306/mydb";
        System.out.println("Connecting to: " + dbUrl);

        // 危险：API密钥
        String apiKey = "sk-1234567890abcdefghijklmnop";
        logger.info("Using API key: " + apiKey);
    }

    public void processPayment(String cardNumber, String idCard) {
        // 危险：打印银行卡号
        System.out.println("Processing card: " + cardNumber); // 6222021234567890123

        // 危险：打印身份证号
        logger.info("User ID card: " + idCard); // 11010519900307234X
    }

    public void awsOperations() {
        // 危险：AWS密钥
        String awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

        log.info("AWS Key: {}", awsAccessKey);
        System.err.println("AWS Secret: " + awsSecretKey);
    }

    // 正常日志（无敏感信息）
    public void normalOperation() {
        // 安全：没有敏感信息
        int userCount = 100;
        logger.info("Total users: " + userCount);
        log.debug("Processing request...");
    }
}

// Android风格示例
class AndroidService {
    private static final String TAG = "AndroidService";

    public void processData(String token, String apiKey) {
        // 危险：使用Android Log打印敏感信息
        android.util.Log.d(TAG, "Token: " + token);
        android.util.Log.e(TAG, "API Key: " + apiKey);
        android.util.Log.i(TAG, "Password: admin123");
    }
}