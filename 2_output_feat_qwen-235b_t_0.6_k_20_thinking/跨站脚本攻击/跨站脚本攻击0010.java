package com.example.payment.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

/**
 * 支付回调处理控制器
 * @author 开发者
 */
@Controller
public class PaymentCallbackController {

    private final PaymentService paymentService = new PaymentService();

    @RequestMapping("/payment")
    public ModelAndView handlePayment(HttpServletRequest request) {
        String callbackUrl = request.getParameter("callback");
        String status = request.getParameter("status");

        // 校验回调地址格式（业务规则）
        if (callbackUrl == null || !callbackUrl.startsWith("https://")) {
            return new ModelAndView("error");
        }

        // 处理支付状态并生成回调响应
        String responseMessage = paymentService.processCallback(callbackUrl, status);

        ModelAndView modelAndView = new ModelAndView("payment_result");
        modelAndView.addObject("message", responseMessage);
        return modelAndView;
    }
}

class PaymentService {
    String processCallback(String callbackUrl, String status) {
        // 记录支付状态到日志（业务需求）
        PaymentLogger.logStatus(status);

        // 构建回调响应内容（含用户输入）
        return "支付完成，回调地址：" + callbackUrl;
    }
}

class PaymentLogger {
    static void logStatus(String status) {
        // 模拟日志记录操作
    }
}