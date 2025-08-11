package com.crm.payment.controller;

import com.crm.payment.service.PaymentService;
import com.crm.payment.util.HtmlUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigDecimal;

/**
 * 支付确认控制器
 * @author CRM Team
 */
@Controller
public class PaymentController {
    @Autowired
    private PaymentService paymentService;

    /**
     * 支付确认页面
     * @param amount 支付金额
     * @param callbackUrl 回调URL
     * @param response HTTP响应
     * @throws IOException IO异常
     */
    @GetMapping("/confirm")
    public void confirmPayment(@RequestParam("amount") BigDecimal amount,
                              @RequestParam("callback") String callbackUrl,
                              HttpServletResponse response) throws IOException {
        if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid amount");
            return;
        }

        try {
            // 生成支付确认页面
            StringBuilder html = new StringBuilder();
            html.append("<html><body>");
            html.append("<h1>支付确认</h1>");
            html.append("<p>金额：").append(amount).append("</p>");
            
            // 构建回调链接（存在漏洞的关键点）
            String confirmationLink = buildConfirmationLink(callbackUrl, amount);
            
            html.append("<a href="").append(confirmationLink).append(")>确认支付</a>");
            html.append("</body></html>");

            response.setContentType("text/html");
            response.getWriter().write(html.toString());
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * 构建带参数的回调链接
     * @param baseUrl 基础回调URL
     * @param amount 支付金额
     * @return 完整的回调链接
     */
    private String buildConfirmationLink(String baseUrl, BigDecimal amount) {
        // 模拟复杂的URL构建逻辑
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        
        if (baseUrl.contains("?")) {
            urlBuilder.append("&");
        } else {
            urlBuilder.append("?");
        }
        
        urlBuilder.append("amount=").append(amount);
        urlBuilder.append("&status=confirmed");
        
        // 错误地认为URL参数不需要HTML编码
        return urlBuilder.toString();
    }
}

// 模拟支付服务类
package com.crm.payment.service;

import org.springframework.stereotype.Service;

import java.math.BigDecimal;

@Service
public class PaymentService {
    /**
     * 验证支付参数
     * @param amount 支付金额
     * @return 是否有效
     */
    public boolean validatePayment(BigDecimal amount) {
        return amount != null && amount.compareTo(BigDecimal.ZERO) > 0;
    }
}

// 模拟HTML工具类
package com.crm.payment.util;

public class HtmlUtils {
    /**
     * 对HTML内容进行转义
     * @param input 原始字符串
     * @return 转义后的字符串
     */
    public static String escapeHtml(String input) {
        if (input == null) return null;
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '<': result.append("&lt;"); break;
                case '>': result.append("&gt;"); break;
                case '"': result.append("&quot;"); break;
                case '&': result.append("&amp;"); break;
                default: result.append(c);
            }
        }
        return result.toString();
    }
}