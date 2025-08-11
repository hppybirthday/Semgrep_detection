import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssApp {
    static List<String> messages = new ArrayList<>();

    public static void main(String[] args) {
        SpringApplication.run(XssApp.class, args);
    }

    @Controller
    static class MsgController {
        @RequestMapping("/post")
        String post(@RequestParam String msg) {
            messages.add(msg);
            return "redirect:/view";
        }

        @RequestMapping("/view")
        String view(Model model) {
            model.addAttribute("messages", messages);
            return "msg_list";
        }
    }
}

// Thymeleaf模板msg_list.html内容：
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <div th:each="message : ${messages}">
//     <p th:text="${message}"></p>  // 漏洞点：直接输出用户输入内容
//   </div>
// </body>
// </html>