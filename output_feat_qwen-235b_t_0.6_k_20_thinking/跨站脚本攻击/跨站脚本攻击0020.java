package com.example.xss;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import javax.servlet.http.HttpServletRequest;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@Controller
class VulnerableController {
    // 反射型XSS漏洞：用户参数直接渲染到HTML
    @GetMapping("/profile")
    public ModelAndView showProfile(@RequestParam("user") String username) {
        ModelAndView mv = new ModelAndView("profile");
        mv.addObject("name", username);
        return mv;
    }

    // 异常处理中的XSS漏洞：错误信息未转义
    @GetMapping("/login")
    public ModelAndView handleLoginError(HttpServletRequest request) {
        ModelAndView mv = new ModelAndView("login");
        mv.addObject("error", request.getParameter("error"));
        return mv;
    }

    // JSON上下文XSS：用户输入污染搜索结果
    @GetMapping("/search")
    public ModelAndView searchContent(@RequestParam("query") String query) {
        ModelAndView mv = new ModelAndView("search");
        mv.addObject("query", query);
        // 模拟搜索结果注入（真实场景可能来自数据库）
        mv.addObject("results", "[{'title':'Test','url':'/"+query+".html'}]");
        return mv;
    }
}