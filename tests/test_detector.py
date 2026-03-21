"""测试日志检测器"""

import pytest
from sensitive_check.detector import (
    Language,
    LogMatch,
    detect_log_functions,
    detect_log_functions_multi_language,
    get_supported_languages,
    LOG_FUNCTIONS,
)


class TestDetector:
    """测试日志检测器"""

    def test_python_print_detection(self):
        """测试Python print检测"""
        code = """
print("Hello, World!")
print(user_password)
print(f"User: {username}, Password: {password}")
"""
        matches = detect_log_functions(code, Language.PYTHON)
        assert len(matches) == 3
        for match in matches:
            assert match.function_name == "print"

    def test_python_logging_detection(self):
        """测试Python logging检测"""
        code = """
import logging
logging.info("User logged in")
logger.debug("Password: " + password)
log.error("Failed with token: " + token)
"""
        matches = detect_log_functions(code, Language.PYTHON)
        assert len(matches) >= 3

    def test_javascript_console_detection(self):
        """测试JavaScript console检测"""
        code = """
console.log("Hello");
console.error("Error: " + error);
console.warn(apiKey);
"""
        matches = detect_log_functions(code, Language.JAVASCRIPT)
        assert len(matches) == 3

    def test_java_system_out_detection(self):
        """测试Java System.out检测"""
        code = """
System.out.println("Hello");
System.err.println("Error");
System.out.print("Test");
"""
        matches = detect_log_functions(code, Language.JAVA)
        assert len(matches) >= 3

    def test_android_log_detection(self):
        """测试Android Log检测"""
        code = """
Log.d("TAG", "Debug message");
Log.e("TAG", "Error: " + error);
Log.i("TAG", "Token: " + token);
"""
        matches = detect_log_functions(code, Language.JAVA)
        android_matches = [m for m in matches if m.function_name == "Android Log"]
        assert len(android_matches) == 3

    def test_go_fmt_detection(self):
        """测试Go fmt检测"""
        code = """
fmt.Println("Hello")
fmt.Printf("Name: %s", name)
fmt.Print("Test")
"""
        matches = detect_log_functions(code, Language.GO)
        assert len(matches) >= 3

    def test_rust_println_detection(self):
        """测试Rust println检测"""
        code = """
println!("Hello");
print!("Test");
log::info!("Info");
"""
        matches = detect_log_functions(code, Language.RUST)
        assert len(matches) >= 3

    def test_c_printf_detection(self):
        """测试C printf检测"""
        code = """
printf("Hello\\n");
fprintf(stderr, "Error");
sprintf(buffer, "Test");
"""
        matches = detect_log_functions(code, Language.C)
        assert len(matches) == 3

    def test_cpp_iostream_detection(self):
        """测试C++ iostream检测"""
        code = """
std::cout << "Hello" << std::endl;
std::cerr << "Error" << std::endl;
cout << "Test";
"""
        matches = detect_log_functions(code, Language.CPP)
        assert len(matches) >= 3

    def test_csharp_console_detection(self):
        """测试C# Console检测"""
        code = """
Console.WriteLine("Hello");
Console.Write("Test");
Console.Error.WriteLine("Error");
"""
        matches = detect_log_functions(code, Language.CSHARP)
        assert len(matches) >= 2

    def test_php_echo_detection(self):
        """测试PHP echo检测"""
        code = """
<?php
echo "Hello";
print_r($data);
var_dump($var);
?>
"""
        matches = detect_log_functions(code, Language.PHP)
        assert len(matches) >= 3

    def test_ruby_puts_detection(self):
        """测试Ruby puts检测"""
        code = """
puts "Hello"
print "Test"
p variable
"""
        matches = detect_log_functions(code, Language.RUBY)
        assert len(matches) == 3

    def test_swift_print_detection(self):
        """测试Swift print检测"""
        code = """
print("Hello")
debugPrint("Debug")
dump(object)
"""
        matches = detect_log_functions(code, Language.SWIFT)
        assert len(matches) == 3

    def test_objective_c_nslog_detection(self):
        """测试Objective-C NSLog检测"""
        code = """
NSLog(@"Hello");
NSLog(@"Token: %@", token);
"""
        matches = detect_log_functions(code, Language.OBJECTIVE_C)
        assert len(matches) == 2

    def test_multi_language_detection(self):
        """测试多语言检测"""
        code = """
print("Python")
console.log("JavaScript")
System.out.println("Java")
"""
        matches = detect_log_functions_multi_language(code)
        assert len(matches) >= 3

    def test_get_supported_languages(self):
        """测试获取支持的语言"""
        languages = get_supported_languages()
        assert Language.PYTHON in languages
        assert Language.JAVASCRIPT in languages
        assert Language.JAVA in languages
        assert Language.UNKNOWN not in languages

    def test_line_number_accuracy(self):
        """测试行号准确性"""
        code = """Line 1
Line 2
print("Line 3")
Line 4
print("Line 5")
"""
        matches = detect_log_functions(code, Language.PYTHON)
        assert len(matches) == 2
        assert matches[0].line_number == 3
        assert matches[1].line_number == 5