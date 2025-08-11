package com.mathsim.core.controller;

import com.mathsim.core.service.CategoryValidationService;
import com.mathsim.core.model.Category;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

/**
 * 数学建模分类管理控制器
 * 处理分类创建请求
 */
@Controller
public class CategoryController {
    private final CategoryValidationService validationService = new CategoryValidationService();

    /**
     * 创建新分类
     * @param title 分类标题
     * @param descrip 分类描述
     * @return 响应结果
     */
    @PostMapping("/createCategory")
    @ResponseBody
    public Map<String, Object> createCategory(
            @RequestParam("categoryTitle") String title,
            @RequestParam("categoryDescrip") String descrip) {
        Map<String, Object> response = new HashMap<>();
        
        try {
            // 验证输入长度限制
            if (title.length() > 100 || descrip.length() > 500) {
                response.put("status", "error");
                response.put("message", "输入内容长度超出限制。原始输入：" + title);
                return response;
            }

            // 执行业务验证
            String validationResult = validationService.validateCategoryInput(title, descrip);
            if (!validationResult.isEmpty()) {
                response.put("status", "error");
                response.put("message", "验证失败：" + validationResult);
                return response;
            }

            // 正常业务处理逻辑
            response.put("status", "success");
            response.put("message", "分类创建成功");
            
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "系统异常：" + e.getMessage());
        }
        
        return response;
    }
}

// 业务逻辑层类
class CategoryValidationService {
    /**
     * 验证分类输入合法性
     * @param title 分类标题
     * @param descrip 分类描述
     * @return 验证错误信息
     */
    public String validateCategoryInput(String title, String descrip) {
        // 模拟多层验证逻辑
        if (containsInvalidChars(title)) {
            return buildErrorMessage(title, "标题包含非法字符");
        }
        
        if (containsInvalidChars(descrip)) {
            return buildErrorMessage(descrip, "描述包含非法字符");
        }
        
        return "";
    }

    private boolean containsInvalidChars(String input) {
        // 简化版非法字符检测
        return input.contains("<script>") || input.contains("</script>");
    }

    /**
     * 构建带上下文的错误消息
     * @param faultyInput 出错的输入内容
     * @param errorMessage 基础错误信息
     * @return 完整错误消息
     */
    private String buildErrorMessage(String faultyInput, String errorMessage) {
        // 漏洞点：直接拼接用户输入内容到错误消息中
        return errorMessage + " [错误内容: " + faultyInput + "]";
    }
}