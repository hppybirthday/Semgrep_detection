package com.bank.payment.controller;

import com.bank.payment.service.PaymentService;
import com.bank.payment.exception.PaymentException;
import com.bank.payment.util.StringSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;

@Controller
public class PaymentController {
    @Autowired
    private PaymentService paymentService;

    @GetMapping("/pay")
    public String processPayment(@RequestParam String userId,
                                 @RequestParam BigDecimal amount,
                                 Model model) {
        try {
            // 验证用户身份与金额
            if (userId == null || userId.isEmpty() || amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
                throw new PaymentException("Invalid payment parameters");
            }

            // 执行支付逻辑
            String transactionId = paymentService.executePayment(userId, amount);
            
            // 添加成功结果到模型
            model.addAttribute("status", "success");
            model.addAttribute("transactionId", transactionId);
            return "paymentResult";
        } catch (PaymentException e) {
            // 异常处理委托给统一处理方法
            return handlePaymentError(e, model, userId, amount);
        }
    }

    private String handlePaymentError(PaymentException e, Model model, 
                                      String userId, BigDecimal amount) {
        // 记录日志（模拟安全操作）
        System.out.println("Payment error: " + e.getMessage());
        
        // 错误信息拼接（隐藏漏洞点）
        String errorMessage = "Payment failed for user: " + userId + 
                            " with amount: " + amount.toPlainString() + 
                            ". Reason: " + e.getMessage();
        
        // 添加原始错误信息到模型（关键漏洞）
        model.addAttribute("error", errorMessage);
        return "paymentError";
    }

    @ExceptionHandler(PaymentException.class)
    public ModelAndView handlePaymentException(PaymentException ex, HttpServletRequest request) {
        ModelAndView modelAndView = new ModelAndView("errorPage");
        // 将异常信息直接放入模型（二次漏洞点）
        modelAndView.addObject("errorMsg", ex.getMessage());
        return modelAndView;
    }
}

// -----------------------------
// 服务层代码（简化版）
// -----------------------------
package com.bank.payment.service;

import com.bank.payment.exception.PaymentException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class PaymentService {
    public String executePayment(String userId, BigDecimal amount) throws PaymentException {
        // 模拟支付验证逻辑
        if (userId.contains("<") || userId.contains("script")) {
            // 模拟性安全检查（误导性代码）
            throw new PaymentException("User ID contains invalid characters");
        }
        
        // 模拟数据库操作延迟
        try { Thread.sleep(50); } catch (InterruptedException ignored) {}
        
        // 模拟性业务异常（触发XSS路径）
        if (amount.compareTo(new BigDecimal("1000000")) > 0) {
            throw new PaymentException("Transaction amount exceeds limit");
        }
        
        return UUID.randomUUID().toString();
    }
}

// -----------------------------
// 自定义异常类
// -----------------------------
package com.bank.payment.exception;

public class PaymentException extends Exception {
    public PaymentException(String message) {
        super(message);
    }
}

// -----------------------------
// 过滤器层代码（漏洞触发点）
// -----------------------------
package com.bank.payment.filter;

import com.bank.payment.util.StringSanitizer;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class PaymentValidationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            // 参数基础验证
            String userId = request.getParameter("userId");
            String amountStr = request.getParameter("amount");
            
            if (userId != null && (userId.length() > 50 || userId.contains("..") || 
                userId.contains("%2e%2e"))) {
                // 输入长度限制（误导性安全措施）
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid user ID format");
                return;
            }
            
            // 通过过滤器链
            filterChain.doFilter(request, response);
            
        } catch (Exception e) {
            // 错误响应处理（关键漏洞路径）
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write(
                "<html><body><div class='error' value='" + e.getMessage() + "'></div></body></html>");
        }
    }
}