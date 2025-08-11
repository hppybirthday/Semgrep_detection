package com.example.payment.controller;

import com.example.payment.model.PaymentRecord;
import com.example.payment.service.PaymentService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequiredArgsConstructor
@RequestMapping("/payments")
public class PaymentController {
    private final PaymentService paymentService;

    @GetMapping("/new")
    public String showPaymentForm(Model model) {
        model.addAttribute("paymentRecord", new PaymentRecord());
        return "payment-form";
    }

    @PostMapping("/process")
    public String processPayment(@ModelAttribute PaymentRecord paymentRecord) {
        // Vulnerable: Directly storing user input without validation
        paymentService.savePayment(paymentRecord);
        return "redirect:/payments/list";
    }

    @GetMapping("/list")
    public String listPayments(Model model) {
        List<PaymentRecord> payments = paymentService.getAllPayments();
        // Vulnerable: Passing untrusted data to template
        model.addAttribute("payments", payments);
        return "payment-list";
    }
}

// Thymeleaf template payment-list.html
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Payment List</title>
    <script th:inline="javascript">
        /*<![CDATA[*/
        document.addEventListener('DOMContentLoaded', function() {
            var payments = /*[(${@org.springframework.web.util.HtmlUtils.htmlEscape(@payments)})]*/ '[]';
            // Vulnerable: Using unsafe JSON parse with untrusted data
            var paymentData = JSON.parse(payments.replace(/&quot;/g, '"'));
            
            // Simulated admin functionality that displays payment details
            paymentData.forEach(function(payment) {
                var div = document.createElement('div');
                // Vulnerable: Directly inserting untrusted data into HTML
                div.innerHTML = '<strong>Callback:</strong> ' + payment.callbackUrl;
                document.body.appendChild(div);
            });
        });
        /*]]>*/
    </script>
</head>
<body>
    <h1>Payment Records</h1>
</body>
</html>
*/

// PaymentRecord.java
package com.example.payment.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "payment_records")
public class PaymentRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String userId;
    private String amount;
    // Vulnerable: Unsanitized callback URL storage
    private String callbackUrl;
}

// PaymentService.java
package com.example.payment.service;

import com.example.payment.model.PaymentRecord;
import com.example.payment.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class PaymentService {
    private final PaymentRepository paymentRepository;

    public void savePayment(PaymentRecord record) {
        // Vulnerable: No input sanitization
        paymentRepository.save(record);
    }

    public List<PaymentRecord> getAllPayments() {
        return paymentRepository.findAll();
    }
}

// PaymentRepository.java
package com.example.payment.repository;

import com.example.payment.model.PaymentRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentRepository extends JpaRepository<PaymentRecord, Long> {}
