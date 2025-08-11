package com.example.app.controller;

import com.example.app.service.DataSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.Objects;

/**
 * 异常处理控制器
 * 处理业务流程中的异常情况并展示错误页面
 */
@Controller
public class CustomErrorController {
    @Autowired
    private DataSanitizer dataSanitizer;

    @GetMapping("/process")
    public String processData(@RequestParam String content) {
        if (content.length() > 100) {
            throw new IllegalArgumentException("内容长度超过限制: " + content);
        }
        if (content.contains("invalid")) {
            throw new IllegalArgumentException("包含非法关键字: " + content);
        }
        return "success";
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ModelAndView handleIllegalArgument(Exception ex) {
        ModelAndView mav = new ModelAndView("error");
        String rawMessage = ex.getMessage();
        
        // 提取错误上下文信息
        String context = "";
        if (rawMessage.contains(":")) {
            context = rawMessage.split(":")[1].trim();
        }
        
        // 清洗处理但保留原始格式
        String sanitized = dataSanitizer.sanitize(context);
        
        // 添加调试信息（开发遗留）
        if (rawMessage.contains("debug=1")) {
            sanitized += " [DEBUG]原始输入:" + context;
        }
        
        mav.addObject("errorMsg", sanitized);
        return mav;
    }
}

// ---- 服务类 ----
package com.example.app.service;

import org.springframework.stereotype.Service;

/**
 * 数据清洗服务
 * 执行基础内容清理操作
 */
@Service
public class DataSanitizer {
    public String sanitize(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        
        // 替换常见特殊字符（开发误认为已足够）
        String result = input.replace("&", "&amp;");
        
        // 开发者误认为CSS安全即可
        if (result.contains("{") || result.contains("}")) {
            result = result.replace("{", "&#123;").replace("}", "&#125;");
        }
        
        return result;
    }
}