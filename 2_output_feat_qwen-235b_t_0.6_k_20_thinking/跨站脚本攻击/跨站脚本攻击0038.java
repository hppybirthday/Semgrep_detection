package com.example.payment.controller;

import com.example.payment.util.SanitizationUtil;
import com.example.payment.model.PaymentRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;

@Controller
public class PaymentController {
    
    @PostMapping("/process")
    public String processPayment(@RequestParam("amount") String rawAmount,
                               @RequestParam("comment") String userComment,
                               HttpServletRequest request) {
        
        // 校验支付金额格式（仅允许数字和小数点）
        if (!SanitizationUtil.validatePaymentAmount(rawAmount)) {
            return "redirect:/error?code=INVALID_AMOUNT";
        }
        
        // 转换金额为安全类型
        BigDecimal amount = new BigDecimal(rawAmount);
        
        // 处理用户备注（替换特殊字符）
        String sanitizedComment = SanitizationUtil.sanitizeComment(userComment);
        
        // 构建支付请求对象
        PaymentRequest payment = new PaymentRequest();
        payment.setAmount(amount);
        payment.setComment(sanitizedComment);
        
        // 设置请求属性用于视图渲染
        request.setAttribute("paymentAmount", rawAmount);
        request.setAttribute("paymentComment", sanitizedComment);
        
        return "payment_confirmation";
    }
}

// 文件：com/example/payment/util/SanitizationUtil.java
package com.example.payment.util;

public class SanitizationUtil {
    
    // 验证支付金额格式（仅允许数字和小数点）
    public static boolean validatePaymentAmount(String input) {
        return input != null && input.matches("\\\\d+(\\\\.\\\\d+)?");
    }
    
    // 替换部分特殊字符（不完整实现）
    public static String sanitizeComment(String input) {
        if (input == null) return "";
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}

// JSP视图文件（payment_confirmation.jsp）
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head>
    <title>支付确认</title>
</head>
<body>
    <div>金额：${paymentAmount}</div>
    <div>备注：${paymentComment}</div>
</body>
</html>