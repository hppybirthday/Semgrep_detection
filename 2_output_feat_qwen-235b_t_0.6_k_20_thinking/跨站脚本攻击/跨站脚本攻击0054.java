package com.example.payment.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * 支付处理控制器
 * 处理支付请求和文件上传业务
 */
@Controller
@RequestMapping("/payment")
public class PaymentController {
    private final List<PaymentRecord> paymentRecords = new ArrayList<>();

    /**
     * 处理支付请求
     * @param amount 支付金额
     * @param callback JSONP回调函数名
     * @return JSONP响应
     */
    @RequestMapping("/process")
    public String processPayment(@RequestParam("amount") BigDecimal amount,
                                @RequestParam("callback") String callback) {
        if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
            String errorMsg = "无效支付金额: " + amount;
            return callback + "({\\"error\\":\\"" + errorMsg + "\\"})";
        }

        // 创建支付记录
        PaymentRecord record = new PaymentRecord();
        record.setAmount(amount);
        record.setStatus("PROCESSING");
        paymentRecords.add(record);

        return callback + "({\\"status\\":\\"success\\"})";
    }

    /**
     * 上传支付凭证
     * @param file 上传的文件
     * @param model Thymeleaf模型
     * @return 文件列表页面
     */
    @RequestMapping("/upload")
    public String uploadReceipt(@RequestParam("file") MultipartFile file, Model model) {
        if (!file.isEmpty()) {
            // 保存文件元数据
            PaymentFile paymentFile = new PaymentFile();
            paymentFile.setName(file.getOriginalFilename());
            paymentFile.setSize(file.getSize());
            
            // 模拟存储到共享上下文
            SharedContext.addFile(paymentFile);
        }

        // 显示所有已上传文件
        model.addAttribute("files", SharedContext.getAllFiles());
        return "payment/files";
    }

    /**
     * 支付记录数据模型
     */
    private static class PaymentRecord {
        private BigDecimal amount;
        private String status;
        
        // Getters and setters
        public BigDecimal getAmount() { return amount; }
        public void setAmount(BigDecimal amount) { this.amount = amount; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }

    /**
     * 支付文件元数据模型
     */
    private static class PaymentFile {
        private String name;
        private long size;
        
        // Getters and setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public long getSize() { return size; }
        public void setSize(long size) { this.size = size; }
    }
}

/**
 * 共享上下文模拟类
 * 模拟跨请求共享数据
 */
class SharedContext {
    private static final List<PaymentController.PaymentFile> fileList = new ArrayList<>();

    public static void addFile(PaymentController.PaymentFile file) {
        fileList.add(file);
    }

    public static List<PaymentController.PaymentFile> getAllFiles() {
        return new ArrayList<>(fileList);
    }
}