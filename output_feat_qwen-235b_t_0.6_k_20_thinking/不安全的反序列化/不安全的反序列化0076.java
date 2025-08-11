package com.crm.payment;

import org.jxls.reader.ReaderBuilder;
import org.jxls.reader.XLSReadStatus;
import org.jxls.reader.XLSReader;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/payments")
public class PaymentController {
    private final PaymentService paymentService = new PaymentService();

    @PostMapping("/import")
    public String importExcel(@RequestParam("file") MultipartFile file) {
        try {
            InputStream input = file.getInputStream();
            XLSReader reader = ReaderBuilder.buildFromXML(this.getClass().getResourceAsStream("/templates/payment_template.xml"));
            PaymentData data = new PaymentData();
            XLSReadStatus status = reader.read(input, data);
            
            // 漏洞点：不安全的反序列化
            if(status.isStatusOK()) {
                for(PaymentCallback callback : data.getCallbacks()) {
                    // 使用FastJSON反序列化回调参数（未启用安全模式）
                    Map<String, Object> params = JSON.parseObject(
                        callback.getRawParams(),
                        Feature.AllowArbitraryInstanceProperties
                    );
                    paymentService.processCallback(callback.getTransactionId(), params);
                }
            }
            return "Import successful";
        } catch (Exception e) {
            return "Import failed: " + e.getMessage();
        }
    }

    static class PaymentData {
        private List<PaymentCallback> callbacks;
        public List<PaymentCallback> getCallbacks() { return callbacks; }
        public void setCallbacks(List<PaymentCallback> callbacks) { this.callbacks = callbacks; }
    }
}

class PaymentCallback {
    private String transactionId;
    private String rawParams; // 存储原始JSON数据
    
    // Getters and setters
    public String getTransactionId() { return transactionId; }
    public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
    public String getRawParams() { return rawParams; }
    public void setRawParams(String rawParams) { this.rawParams = rawParams; }
}

class PaymentService {
    public void processCallback(String txId, Map<String, Object> params) {
        // 模拟业务处理
        System.out.println("Processing payment: " + txId);
        params.forEach((k,v) -> System.out.println(k + ": " + v));
    }
}