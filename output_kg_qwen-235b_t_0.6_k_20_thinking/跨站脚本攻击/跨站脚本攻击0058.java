package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class UserController {
    
    private static final Map<String, String> users = new HashMap<>();
    
    static {
        // 初始化测试用户
        users.put("1", "<script>alert('xss')</script>");
        users.put("2", "<b>JohnDoe</b>");
    }

    public static void main(String[] args) {
        SpringApplication.run(UserController.class, args);
    }

    @GetMapping(path = "/user/{id}", produces = MediaType.TEXT_HTML_VALUE)
    public String getUserProfile(@PathVariable String id) {
        // 漏洞点：直接拼接HTML内容
        return buildHtmlContent(users::get, id);
    }

    // 函数式风格构建HTML内容
    private static Function<String, String> buildHtmlContent = 
        userGetter -> id -> {
            String unsafeContent = userGetter.apply(id);
            return String.format(
                "<html><body><h1>User Profile</h1><div>%s</div></body></html>",
                unsafeContent != null ? unsafeContent : "User not found"
            );
        };

    // 模拟用户注册接口（存在相同漏洞）
    @PostMapping(path = "/register", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public String registerUser(@RequestParam Map<String, String> formData) {
        String userId = String.valueOf(users.size() + 1);
        String nickname = formData.get("nickname");
        
        // 存储原始输入
        users.put(userId, nickname);
        
        // 生成包含用户输入的响应页面
        return String.format(
            "<html><body><h2>Registration Success</h2><div>New user: %s</div></body></html>",
            nickname
        );
    }

    // 静态方法引用演示
    private static String processUserInput(Function<String, String> processor, String input) {
        return processor.apply(input);
    }

    // 辅助类模拟HTML构建
    static class HtmlBuilder {
        static String createPage(String content) {
            return "<html><body>" + content + "</body></html>";
        }
    }
}

// 漏洞特征说明：
// 1. 用户输入直接拼接到HTML响应中
// 2. 未进行HTML转义处理
// 3. 同时存在于GET和POST接口
// 4. 使用函数式编程风格时忽视了输入验证