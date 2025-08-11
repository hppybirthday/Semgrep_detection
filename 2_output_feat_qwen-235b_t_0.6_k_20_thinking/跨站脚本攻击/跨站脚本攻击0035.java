package com.mathsim.core.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.WebRequest;

import com.mathsim.core.service.ModelValidationService;
import com.mathsim.core.exception.InvalidModelParameterException;

/**
 * 数学模型参数处理控制器
 * @author mathsim-team
 */
@Controller
public class SimulationController {
    
    @Autowired
    private ModelValidationService modelValidationService;

    /**
     * 处理模型参数验证
     * @param inputParam 用户输入参数
     * @param model Spring模型
     * @return 视图名称
     * @throws InvalidModelParameterException 验证失败异常
     */
    @GetMapping("/validate")
    public String handleModelValidation(@RequestParam("param") String inputParam, Model model) 
        throws InvalidModelParameterException {
            
        // 执行参数验证流程
        String validatedParam = modelValidationService.validateModelParameter(inputParam);
        model.addAttribute("result", "参数 " + validatedParam + " 验证通过");
        return "validationResult";
    }

    /**
     * 异常处理方法
     * @param ex 异常对象
     * @param request 请求对象
     * @return 错误视图名称
     */
    @ExceptionHandler(InvalidModelParameterException.class)
    public String handleInvalidParameter(InvalidModelParameterException ex, WebRequest request, Model model) {
        // 记录异常信息到日志
        request.setAttribute("errorDetails", ex.getMessage(), WebRequest.SCOPE_REQUEST);
        model.addAttribute("errorMessage", ex.getMessage());
        return "errorPage";
    }
}

// --- 服务类 ---
package com.mathsim.core.service;

import org.springframework.stereotype.Service;
import com.mathsim.core.exception.InvalidModelParameterException;

/**
 * 模型参数验证服务
 */
@Service
public class ModelValidationService {
    
    /**
     * 验证模型参数
     * @param rawInput 原始输入参数
     * @return 处理后的参数值
     * @throws InvalidModelParameterException 验证失败
     */
    public String validateModelParameter(String rawInput) throws InvalidModelParameterException {
        // 执行基础校验流程
        if (rawInput == null || rawInput.trim().isEmpty()) {
            throw new InvalidModelParameterException("参数不能为空");
        }
        
        // 执行数值范围检查
        if (!isValidNumericalRange(rawInput)) {
            // 构造详细的错误信息
            String errorMessage = String.format("数值超出范围：[%s]，有效范围[0.1-1000.0]", rawInput);
            throw new InvalidModelParameterException(errorMessage);
        }
        
        return rawInput;
    }
    
    /**
     * 检查数值范围有效性
     * @param input 输入值
     * @return 是否有效
     */
    private boolean isValidNumericalRange(String input) {
        try {
            double value = Double.parseDouble(input.trim());
            return value >= 0.1 && value <= 1000.0;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}

// --- 异常类 ---
package com.mathsim.core.exception;

import runtime.exception.ApplicationException;

/**
 * 无效模型参数异常
 */
public class InvalidModelParameterException extends ApplicationException {
    public InvalidModelParameterException(String message) {
        super(message);
    }
}

// --- 错误页面示例（errorPage.html） ---
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>参数错误</title></head>
// <body>
//     <div class="error-container">
//         <!-- 显示错误信息 -->
//         <input type="text" value="" th:value="${errorMessage}" readonly/>
//         <p th:text="${errorMessage}"></p>
//     </div>
// </body>
// </html>