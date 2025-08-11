import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssVulnerableApp {
    private static List<String> comments = new ArrayList<>();

    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }

    @Controller
    public static class CommentController {
        @GetMapping("/")
        public String showComments(Model model) {
            model.addAttribute("comments", comments);
            return "comments";
        }

        @PostMapping("/add")
        public String addComment(@RequestParam String comment, HttpServletRequest request) {
            // 漏洞点：直接存储用户输入
            comments.add(comment);
            // 错误地将原始输入设置为请求属性
            request.setAttribute("rawInput", comment);
            return "redirect:/";
        }

        @GetMapping("/error")
        public String handleError(HttpServletRequest request) {
            // 漏洞点：直接输出异常路径中的用户输入
            String path = (String) request.getAttribute("javax.servlet.error.request_uri");
            request.setAttribute("errorMsg", "Invalid path: " + path);
            return "error";
        }
    }
}

// Thymeleaf模板（resources/templates/comments.html）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Comments</title></head>
<body>
    <h1>Comments</h1>
    <form action="/add" method="post">
        <textarea name="comment"></textarea>
        <button type="submit">Submit</button>
    </form>
    
    <div th:each="c : ${comments}">
        <!-- 漏洞点：直接输出用户输入内容 -->
        <div th:utext="${c}"></div>
    </div>
    
    <!-- 漏洞点：显示原始输入 -->
    <div th:if="${#request.getAttribute('rawInput')} != null">
        Last submitted: <span th:text="${#request.getAttribute('rawInput')}"></span>
    </div>
</body>
</html>
*/

// Thymeleaf模板（resources/templates/error.html）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Error</title></head>
<body>
    <!-- 漏洞点：直接输出错误路径 -->
    <div th:text="${errorMsg}"></div>
</body>
</html>
*/

// application.properties配置
/*
spring.thymeleaf.cache=false
spring.thymeleaf.mode=HTML
server.error.path=/error
*/