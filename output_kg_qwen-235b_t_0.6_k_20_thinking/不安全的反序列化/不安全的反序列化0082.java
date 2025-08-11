package com.example.vulnerableapp.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/payment")
public class PaymentController {

    @PostMapping("/process")
    public ResponseEntity<String> processPayment(@RequestBody PaymentRequest request) {
        String encodedData = request.getSerializedData();
        if (encodedData == null || encodedData.isEmpty()) {
            return ResponseEntity.badRequest().body("Missing data");
        }

        try {
            byte[] data = Base64.getDecoder().decode(encodedData);
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            UnsafeObjectInputStream ois = new UnsafeObjectInputStream(bis);
            Object obj = ois.readObject();
            
            if (obj instanceof PaymentDetails) {
                PaymentDetails details = (PaymentDetails) obj;
                return ResponseEntity.ok("Processed payment: $" + details.getAmount());
            } else {
                return ResponseEntity.badRequest().body("Invalid data type");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Internal error");
        }
    }

    class UnsafeObjectInputStream extends ObjectInputStream {
        public UnsafeObjectInputStream(ByteArrayInputStream bis) throws IOException {
            super(bis);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {
            return Class.forName(desc.getName(), false, getClass().getClassLoader());
        }
    }

    static class PaymentRequest {
        private String serializedData;

        public String getSerializedData() { return serializedData; }
        public void setSerializedData(String serializedData) { this.serializedData = serializedData; }
    }

    static class PaymentDetails implements java.io.Serializable {
        private Double amount;
        private String currency;

        public Double getAmount() { return amount; }
        public void setAmount(Double amount) { this.amount = amount; }
        
        public String getCurrency() { return currency; }
        public void setCurrency(String currency) { this.currency = currency; }
    }
}