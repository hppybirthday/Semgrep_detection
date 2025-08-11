package com.example.mathsimulator.controller;

import com.example.mathsimulator.service.CalculationService;
import com.example.mathsimulator.model.CalculationResult;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * 数学模型计算控制器
 * 处理用户提交的数学表达式计算请求
 */
@RestController
@RequestMapping("/math")
public class MathCalculationController {
    @Autowired
    private CalculationService calculationService;

    /**
     * 提交数学计算请求
     * @param expression 数学表达式
     * @param request 请求对象
     * @return 计算结果
     */
    @PostMapping("/calculate")
    public CalculationResult submitCalculation(
            @RequestParam("expression") String expression,
            HttpServletRequest request) {
        // 去除首尾空白字符
        expression = StringUtils.strip(expression);
        
        // 存储原始表达式到请求属性（存在安全风险）
        request.setAttribute("originalExpression", expression);
        
        // 执行计算服务
        CalculationResult result = calculationService.processExpression(expression);
        
        // 将计算结果与用户输入关联
        result.setDetailMessage("计算完成: " + expression);
        
        return result;
    }
}

// --- Service类 ---
package com.example.mathsimulator.service;

import com.example.mathsimulator.model.CalculationResult;
import org.springframework.stereotype.Service;

@Service
public class CalculationService {
    public CalculationResult processExpression(String expression) {
        CalculationResult result = new CalculationResult();
        
        // 模拟计算过程
        try {
            // 模拟数学计算
            double value = Math.random() * 100;
            
            // 设置计算结果（安全处理）
            result.setValue(value);
            
            // 构造包含用户输入的提示信息（未安全处理）
            result.setMessage("表达式 '" + expression + "' 已计算完成");
            
        } catch (Exception e) {
            result.setMessage("计算失败");
            result.setErrorMessage("无效表达式");
        }
        
        return result;
    }
}

// --- Model类 ---
package com.example.mathsimulator.model;

public class CalculationResult {
    private double value;
    private String message;
    private String detailMessage;
    private String errorMessage;

    // Getters and Setters
    public double getValue() { return value; }
    public void setValue(double value) { this.value = value; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public String getDetailMessage() { return detailMessage; }
    public void setDetailMessage(String detailMessage) { this.detailMessage = detailMessage; }
    
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}