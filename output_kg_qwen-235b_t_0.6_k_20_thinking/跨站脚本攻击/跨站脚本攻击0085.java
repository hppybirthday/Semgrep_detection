package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
class BankController {
    private static List<Transaction> transactions = new ArrayList<>();

    @GetMapping("/transfer")
    public String transferForm() {
        return "<html><body><form action='/transfer' method='post'>"
            + "To: <input type='text' name='to'/><br/>"
            + "Amount: <input type='text' name='amount'/><br/>"
            + "<input type='submit' value='Transfer'/>"
            + "</form></body></html>";
    }

    @PostMapping("/transfer")
    public String processTransfer(@RequestParam String to, @RequestParam String amount) {
        transactions.add(new Transaction(to, amount));
        return "<html><body><h2>Transfer Successful!</h2>"
            + "<p>To: " + to + "</p>"
            + "<p>Amount: " + amount + "</p>"
            + "<h3>Recent Transactions:</h3>"
            + "<ul>"
            + transactions.stream().map(t -> "<li>To: " + t.to + " - Amount: " + t.amount + "</li>").collect(java.util.stream.Collectors.joining())
            + "</ul>"
            + "</body></html>";
    }
}

class Transaction {
    String to;
    String amount;

    Transaction(String to, String amount) {
        this.to = to;
        this.amount = amount;
    }
}