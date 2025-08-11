import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@SpringBootApplication
public class BankApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/api")
class TransactionController {
    private final TransactionService transactionService;

    public TransactionController(TransactionService transactionService) {
        this.transactionService = transactionService;
    }

    @GetMapping("/transactions")
    public String getExternalTransactions(@RequestParam String url) {
        return transactionService.fetchTransactions(url);
    }
}

class TransactionService {
    private final RestTemplate restTemplate;

    public TransactionService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchTransactions(String url) {
        try {
            return restTemplate.getForObject(new URI(url), String.class);
        } catch (Exception e) {
            return "Error fetching transactions: " + e.getMessage();
        }
    }
}

class Account {
    private String accountId;
    private double balance;
    // getters and setters
}