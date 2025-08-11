package com.enterprise.payment.controller;

import com.enterprise.payment.service.PaymentService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

/**
 * 支付确认控制器
 * 处理支付结果展示逻辑
 */
@Controller
public class PaymentConfirmationController {
    private final PaymentService paymentService;

    public PaymentConfirmationController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    /**
     * 展示支付确认页面
     * @param userId 用户标识
     * @param orderId 订单编号
     * @return 渲染后的视图
     */
    @GetMapping("/confirm")
    public ModelAndView showConfirmation(@RequestParam String userId, @RequestParam String orderId) {
        Map<String, Object> model = new HashMap<>();
        
        // 构造支付确认信息
        model.put("paymentInfo", paymentService.getPaymentDetails(userId, orderId));
        
        // 生成客户端配置
        model.put("clientConfig", generateClientConfig(userId));
        
        return new ModelAndView("payment-confirmation", model);
    }

    private Map<String, String> generateClientConfig(String userIdentifier) {
        Map<String, String> config = new HashMap<>();
        // 构建客户端监控脚本配置
        config.put("monitorScript", String.format("trackPayment('%s')", userIdentifier));
        return config;
    }
}