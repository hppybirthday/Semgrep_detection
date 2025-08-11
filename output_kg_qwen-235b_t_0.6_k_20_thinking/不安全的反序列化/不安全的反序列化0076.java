package com.example.payment.service;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/callback")
public class PaymentCallbackController {
    private final PaymentService paymentService;

    public PaymentCallbackController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    @PostMapping("/process")
    public String handleCallback(@RequestBody CallbackRequest request) {
        try {
            paymentService.processPaymentCallback(request.getSerializedData());
            return "SUCCESS";
        } catch (Exception e) {
            return "ERROR";
        }
    }
}

class CallbackRequest {
    private String serializedData;

    public String getSerializedData() {
        return serializedData;
    }

    public void setSerializedData(String serializedData) {
        this.serializedData = serializedData;
    }
}

interface PaymentCallbackHandler {
    Object deserialize(String data) throws IOException, ClassNotFoundException;
}

class UnsafeDeserializationHandler implements PaymentCallbackHandler {
    @Override
    public Object deserialize(String data) throws IOException, ClassNotFoundException {
        byte[] decodedBytes = Base64.getDecoder().decode(data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decodedBytes))) {
            return ois.readObject(); // 不安全的反序列化
        }
    }
}

@Service
class PaymentService {
    private final PaymentCallbackHandler callbackHandler;

    public PaymentService(PaymentCallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    public void processPaymentCallback(String serializedData) throws Exception {
        Object callbackData = callbackHandler.deserialize(serializedData);
        if (callbackData instanceof PaymentResponse) {
            ((PaymentResponse) callbackData).process();
        }
    }
}

@Data
@AllArgsConstructor
@NoArgsConstructor
class PaymentResponse implements Serializable {
    private String transactionId;
    private double amount;
    private String status;

    public void process() {
        System.out.println("Processing payment: " + transactionId + " | " + amount);
    }
}

@Configuration
class PaymentConfig {
    @Bean
    PaymentCallbackHandler paymentCallbackHandler() {
        return new UnsafeDeserializationHandler();
    }

    @Bean
    PaymentService paymentService(PaymentCallbackHandler handler) {
        return new PaymentService(handler);
    }
}