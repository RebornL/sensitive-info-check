// 测试样例 - JavaScript
// 此文件包含一些敏感日志打印示例

// 用户登录处理
function handleLogin(username, password) {
    // 危险：打印密码
    console.log(`User login: ${username}, password: ${password}`);

    // 危险：使用console.error打印密码
    console.error(`Login failed for password: ${password}`);

    // 危险：console.info打印敏感信息
    console.info(`Auth token: ${authToken}`);
}

// API调用
function callApi() {
    // 危险：API密钥
    const apiKey = "sk-1234567890abcdefghijklmnop";
    console.log(`Calling API with key: ${apiKey}`);

    // 危险：访问令牌
    const accessToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    console.debug(`Access token: ${accessToken}`);
}

// 用户信息处理
function processUserInfo(user) {
    // 危险：打印手机号
    console.log(`User phone: ${user.phone}`); // 13812345678

    // 危险：打印邮箱
    console.log(`User email: ${user.email}`); // user@example.com

    // 危险：打印身份证号
    console.warn(`ID Card: ${user.idCard}`); // 11010519900307234X
}

// 数据库操作
function connectDB() {
    // 危险：数据库连接串
    const dbUrl = "mongodb://admin:password123@localhost:27017/mydb";
    console.log(`Connecting to: ${dbUrl}`);

    // 危险：AWS密钥
    const awsKey = "AKIAIOSFODNN7EXAMPLE";
    console.log(`AWS Key: ${awsKey}`);
}

// 正常日志（无敏感信息）
function normalOperation() {
    // 安全：没有敏感信息
    const userCount = 100;
    console.log(`Total users: ${userCount}`);
    console.info("Application started");
}

// 敏感配置（直接暴露）
const config = {
    password: "admin123",
    apiKey: "sk-1234567890abcdef",
    awsSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7k0A0
-----END RSA PRIVATE KEY-----`
};

// 打印配置（危险）
console.log("Config:", config);