package com.example.bank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class BankingApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankingApplication.class, args);
    }
}

@Controller
class PaymentController {
    @GetMapping("/transfer/{amount}")
    public String showPayment(@PathVariable String amount, Model model) {
        model.addAttribute("amount", amount);
        return "payment";
    }

    @GetMapping("/xss-callback")
    public String xssCallback(@RequestParam String callback, @RequestParam String name) {
        // 漏洞点：未对用户输入name进行过滤或转义，直接拼接到JSONP响应中
        return callback + "({'status':'success','name':'" + name + "','redirect:'/dashboard'});";
    }

    @PostMapping("/dynamic-form")
    @ResponseBody
    public Map<String, String> dynamicForm(@RequestParam String field) {
        // 元编程特性：动态生成表单字段配置
        Map<String, String> config = new HashMap<>();
        config.put("fieldName", field);
        config.put("label", "Enter " + field + " value:");
        // 漏洞点：动态生成的前端代码包含未经验证的用户输入
        config.put("template", "<input type='text' name='" + field + "' placeholder='" + field + "'>");
        return config;
    }
}

// Thymeleaf模板：resources/templates/payment.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head>
//     <title>Payment</title>
//     <script th:inline="javascript">
//         /*<![CDATA[*/
//         var amount = /*[(${amount})]*/ '0';
//         var script = document.createElement('script');
//         // 漏洞点：动态加载包含用户输入的JSONP脚本
//         script.src = '/xss-callback?callback=handleResponse&name=' + encodeURIComponent(amount);
//         document.head.appendChild(script);
//         /*]]>*/
//     </script>
// </head>
// <body>
//     <h1>Payment Confirmation</h1>
//     <div id="form-container"></div>
//     <script>
//         function handleResponse(data) {
//             // 漏洞点：直接执行JSONP返回的恶意代码
//             eval(data.redirect);
//         }
//         
//         // 使用动态表单生成接口
//         fetch('/dynamic-form?field=' + amount)
//             .then(res => res.json())
//             .then(config => {
//                 // 漏洞点：直接插入动态生成的HTML模板
//                 document.getElementById('form-container').innerHTML = config.template;
//             });
//     </script>
// </body>
// </html>