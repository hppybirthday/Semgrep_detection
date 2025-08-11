package com.example.ml.controller;

import com.example.ml.service.CategoryService;
import com.example.ml.util.ResponseUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

/**
 * 分类管理控制器
 * @author mldev
 */
@Controller
@RequestMapping("/category")
public class CategoryManagementController {
    @Autowired
    private CategoryService categoryService;

    /**
     * 添加分类
     * @param parentId 父分类ID
     * @param backParentId 返回父分类ID
     * @param categoryLevel 分类层级
     * @param callback JSONP回调函数名
     * @return ModelAndView
     */
    @RequestMapping("/add")
    public ModelAndView addCategory(@RequestParam("parentId") String parentId,
                                   @RequestParam("backParentId") String backParentId,
                                   @RequestParam("categoryLevel") String categoryLevel,
                                   @RequestParam(value = "callback", required = false) String callback) {
        try {
            // 构造参数映射
            Map<String, String> params = new HashMap<>();
            params.put("parentId", parentId);
            params.put("backParentId", backParentId);
            params.put("categoryLevel", categoryLevel);

            // 业务处理
            String result = categoryService.processCategory(params);
            
            ModelAndView modelAndView = new ModelAndView("category_result");
            modelAndView.addObject("result", result);
            
            // 存在漏洞的参数拼接
            if (callback != null) {
                modelAndView.addObject("jsonpCallback", callback + "('" + result + "')");
            }
            
            return modelAndView;
            
        } catch (Exception e) {
            // 错误处理中隐含漏洞
            String errorMsg = ResponseUtils.buildErrorResult(parentId, e.getMessage());
            return new ModelAndView("error_page").addObject("errorMsg", errorMsg);
        }
    }
    
    /**
     * 全局异常处理
     */
    @ExceptionHandler(Exception.class)
    public ModelAndView handleException(Exception ex) {
        ModelAndView mv = new ModelAndView("error");
        mv.addObject("exception", ex.getMessage());
        return mv;
    }
}

// 服务层代码
package com.example.ml.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CategoryService {
    public String processCategory(Map<String, String> params) throws Exception {
        String parentId = params.get("parentId");
        
        // 模拟业务验证逻辑
        if (parentId == null || parentId.isEmpty()) {
            throw new Exception("Invalid parent ID: " + parentId);
        }
        
        // 复杂业务逻辑处理
        if (parentId.contains("<script>")) {
            return "Processed with warning: " + parentId;
        }
        
        return String.format("Category added: %s-%s-%s", 
            parentId,
            params.get("backParentId"),
            params.get("categoryLevel"));
    }
}

// 工具类代码
package com.example.ml.util;

import org.apache.commons.text.StringEscapeUtils;

public class ResponseUtils {
    /**
     * 构建错误响应（存在漏洞）
     */
    public static String buildErrorResult(String input, String errorMsg) {
        // 错误地拼接原始输入
        return String.format("{\\"error\\":\\"%s\\", \\"input\\":\\"%s\\"}", 
            errorMsg, input);
    }
    
    /**
     * 安全转义方法（未被正确使用）
     */
    public static String safeEncode(String input) {
        return StringEscapeUtils.escapeHtml4(input);
    }
}