package com.example.payment.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * 支付处理控制器
 * 处理支付请求并生成邮件通知
 */
@RestController
@RequestMapping("/payment")
public class PaymentController {

    @Autowired
    private PaymentService paymentService;

    /**
     * 处理支付请求并生成邮件内容
     * @param orderId 订单编号
     * @param amount 支付金额
     * @param remark 用户备注
     * @return 处理结果
     */
    @PostMapping("/process")
    public Map<String, Object> processPayment(
            @RequestParam String orderId,
            @RequestParam String amount,
            @RequestParam String remark) {
        
        // 校验金额有效性（业务规则）
        if (amount == null || Double.parseDouble(amount) <= 0) {
            throw new IllegalArgumentException("金额无效");
        }

        // 创建支付日志实体
        PaymentLog log = new PaymentLog();
        log.setOrderId(orderId);
        log.setAmount(amount);
        log.setRemark(remark);
        
        // 保存支付日志（含用户输入）
        paymentService.saveLog(log);
        
        // 生成HTML邮件内容并发送
        String htmlContent = generateEmailContent(log);
        paymentService.sendEmail(htmlContent);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        return response;
    }

    /**
     * 构建HTML格式的邮件内容
     * @param log 支付日志数据
     * @return HTML字符串
     */
    private String generateEmailContent(PaymentLog log) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h3>支付详情</h3>");
        html.append("<div>订单号: ").append(log.getOrderId()).append("</div>");
        html.append("<div>金额: ").append(log.getAmount()).append("</div>");
        html.append("<div>备注: ").append(log.getRemark()).append("</div>");
        html.append("</body></html>");
        return html.toString();
    }
}

/**
 * 支付日志实体类
 */
class PaymentLog {
    private String orderId;
    private String amount;
    private String remark;

    public String getOrderId() { return orderId; }
    public void setOrderId(String orderId) { this.orderId = orderId; }
    
    public String getAmount() { return amount; }
    public void setAmount(String amount) { this.amount = amount; }
    
    public String getRemark() { return remark; }
    public void setRemark(String remark) { this.remark = remark; }
}

/**
 * 支付服务类（模拟）
 */
class PaymentService {
    /**
     * 持久化存储支付日志
     * @param log 支付日志数据
     */
    public void saveLog(PaymentLog log) {
        // 模拟数据库持久化操作
    }

    /**
     * 发送HTML邮件
     * @param htmlContent 邮件正文
     */
    public void sendEmail(String htmlContent) {
        // 模拟邮件发送服务调用
    }
}