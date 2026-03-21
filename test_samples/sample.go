// 测试样例 - Go
// 此文件包含一些敏感日志打印示例

package main

import (
	"fmt"
	"log"
)

// 用户登录处理
func handleLogin(username, password string) {
	// 危险：打印密码
	fmt.Printf("User login: %s, password: %s\n", username, password)

	// 危险：使用log包打印密码
	log.Println("Login attempt with password:", password)
}

// API调用
func callAPI() {
	// 危险：API密钥
	apiKey := "sk-1234567890abcdefghijklmnop"
	fmt.Println("Calling API with key:", apiKey)

	// 危险：访问令牌
	accessToken := "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	log.Printf("Access token: %s", accessToken)
}

// 用户信息处理
func processUserInfo(phone, email, idCard string) {
	// 危险：打印手机号
	fmt.Printf("User phone: %s\n", phone) // 13812345678

	// 危险：打印邮箱
	log.Println("User email:", email) // user@example.com

	// 危险：打印身份证号
	fmt.Printf("ID Card: %s\n", idCard) // 11010519900307234X
}

// 数据库操作
func connectDB() {
	// 危险：数据库连接串
	dbURL := "mysql://admin:password123@localhost:3306/mydb"
	log.Println("Connecting to:", dbURL)

	// 危险：AWS密钥
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	fmt.Println("AWS Key:", awsKey)
}

// 正常日志（无敏感信息）
func normalOperation() {
	// 安全：没有敏感信息
	userCount := 100
	log.Printf("Total users: %d", userCount)
	fmt.Println("Application started")
}

func main() {
	// 测试各种场景
	handleLogin("admin", "admin123")
	callAPI()
	processUserInfo("13812345678", "user@example.com", "11010519900307234X")
	connectDB()
	normalOperation()
}