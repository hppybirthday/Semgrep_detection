package com.bank.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.apache.ibatis.annotations.*;
import java.util.List;

@SpringBootApplication
public class SqlInjectionDemo {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemo.class, args);
    }
}

@RestController
@RequestMapping("/api")
class AccountController {
    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        try {
            Account account = accountService.findAccount(username, password);
            return String.format("Welcome %s! Balance: $%.2f", account.username, account.balance);
        } catch (Exception e) {
            return "Login failed: Invalid credentials";
        }
    }
}

@Service
class AccountService {
    private final AccountMapper accountMapper;

    public AccountService(AccountMapper accountMapper) {
        this.accountMapper = accountMapper;
    }

    public Account findAccount(String username, String password) {
        List<Account> accounts = accountMapper.findByCredentials(username, password);
        return accounts.isEmpty() ? null : accounts.get(0);
    }
}

@Mapper
interface AccountMapper {
    @Select({"<script>",
      "SELECT * FROM accounts WHERE username = '${username}' AND password = '${password}'",
      "</script>"})
    List<Account> findByCredentials(@Param("username") String username, @Param("password") String password);
}

record Account(String username, double balance) {}
