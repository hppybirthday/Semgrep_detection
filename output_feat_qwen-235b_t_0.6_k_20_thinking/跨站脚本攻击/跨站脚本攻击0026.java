package com.example.xss;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class XssDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssDemoApplication.class, args);
    }
}

@Controller
class XssController {
    private static final List<String> userData = new ArrayList<>();

    @GetMapping("/")
    public String form() {
        return "<html><body>" +
               "<h2>Data Cleaning Form</h2>" +
               "<form method='post' action='/clean'>" +
               "Input: <input type='text' name='content'>" +
               "<input type='submit' value='Submit'>" +
               "</form></body></html>";
    }

    @PostMapping("/clean")
    public String process(@RequestParam String content) {
        // 模拟不充分的数据清洗
        String cleaned = content.replaceAll("<script>", ""); // 仅移除<script>标签
        userData.add(cleaned);
        return "Data processed! <a href='/view'>View result</a>";
    }

    @GetMapping("/view")
    public String view() {
        StringBuilder html = new StringBuilder("<html><body>\
");
        html.append("<h2>Cleaned Data:</h2>\
<ul>\
");
        for (String data : userData) {
            // 在HTML属性中直接插入用户数据
            html.append("<li><a href='http://example.com/").append(data)
                 .append("'>Link to ").append(data).append("</a></li>\
");
        }
        html.append("</ul></body></html>");
        return html.toString();
    }
}