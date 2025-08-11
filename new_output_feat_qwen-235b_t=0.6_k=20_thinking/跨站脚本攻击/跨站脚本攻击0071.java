package com.bank.payment.controller;

import com.bank.payment.service.PaymentService;
import com.bank.payment.model.Transaction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Handles payment transactions and user notifications
 * @author Bank Security Team
 */
@Controller
@RequestMapping("/payment")
public class PaymentController {
    
    @Autowired
    private PaymentService paymentService;

    /**
     * Process payment request with user-provided note
     * @param amount Transaction amount
     * @param recipient Account number of recipient
     * @param note User-provided transaction note
     * @param model View model
     * @return View name for transaction confirmation
     */
    @PostMapping("/transfer")
    public String processPayment(@RequestParam("amount") double amount,
                               @RequestParam("recipient") String recipient,
                               @RequestParam("note") String note,
                               Model model) {
        
        if (amount <= 0 || recipient == null || note == null) {
            return "error/invalid_params";
        }

        try {
            // Process transaction and clean input
            Transaction tx = paymentService.createTransaction(amount, recipient, note);
            
            // Store in request attribute for notification
            HttpServletRequest request = ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getRequest();
            request.setAttribute("latestNote", tx.getNote());
            
            model.addAttribute("transaction", tx);
            return "confirmation/success";
            
        } catch (Exception e) {
            return "error/processing";
        }
    }

    /**
     * Display user transaction history
     * @param model View model
     * @return View name for transaction history
     */
    @GetMapping("/history")
    public String showHistory(Model model) {
        model.addAttribute("transactions", paymentService.getAllTransactions());
        return "history/list";
    }
}

// Service Layer
package com.bank.payment.service;

import com.bank.payment.model.Transaction;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Payment processing business logic
 * @author Bank Security Team
 */
@Service
public class PaymentService {
    
    private List<Transaction> transactions = new ArrayList<>();

    /**
     * Create and store new transaction
     * @param amount Transaction amount
     * @param recipient Recipient account
     * @param note User note
     * @return Created transaction
     */
    public Transaction createTransaction(double amount, String recipient, String note) {
        Transaction tx = new Transaction();
        tx.setId(generateUniqueId());
        tx.setAmount(amount);
        tx.setRecipient(recipient);
        tx.setNote(sanitizeInput(note)); // Note cleaning
        tx.setStatus("COMPLETED");
        
        transactions.add(tx);
        return tx;
    }

    /**
     * Sanitize user input according to security policy
     * @param input User-provided string
     * @return Cleaned string
     */
    private String sanitizeInput(String input) {
        // Security measure: Remove whitespace characters
        // Note: This is insufficient for HTML output
        return input.replaceAll("\\\\s+", "");
    }

    /**
     * Get all transactions for history display
     * @return List of transactions
     */
    public List<Transaction> getAllTransactions() {
        return new ArrayList<>(transactions);
    }

    /**
     * Generate unique transaction ID
     * @return New transaction ID
     */
    private String generateUniqueId() {
        return String.format("TX%016x", System.currentTimeMillis());
    }
}

// Model Class
package com.bank.payment.model;

/**
 * Transaction data model
 * @author Bank Security Team
 */
public class Transaction {
    private String id;
    private double amount;
    private String recipient;
    private String note;
    private String status;

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public double getAmount() { return amount; }
    public void setAmount(double amount) { this.amount = amount; }
    
    public String getRecipient() { return recipient; }
    public void setRecipient(String recipient) { this.recipient = recipient; }
    
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}

// Thymeleaf Template (history/list.html)
/*
<div th:each="tx : ${transactions}">
    <p>Amount: <span th:text="${tx.amount}"></span></p>
    <p>Note: <span th:text="${tx.note}"></span></p>  <!-- XSS Vulnerability Here -->
</div>
*/