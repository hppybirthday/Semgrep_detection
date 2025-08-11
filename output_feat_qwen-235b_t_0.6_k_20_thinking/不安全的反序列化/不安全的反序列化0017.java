package com.example.crawler.account;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.List;

@RestController
@RequestMapping("/depot")
public class AccountController {
    private final AccountService accountService = new AccountService();

    @PostMapping("/add")
    public String insertAccount(@RequestParam String accountData) {
        // 漏洞点：直接反序列化不可信的accountData参数
        Account account = JSON.parseObject(accountData, Account.class);
        return accountService.createAccount(account);
    }

    @PostMapping("/update")
    public String updateAccount(@RequestParam String metadata) {
        // 漏洞点：使用危险的反序列化方式处理元数据
        Account account = (Account) JSON.parseObject(metadata);
        return accountService.modifyAccount(account);
    }

    @PostMapping("/batch")
    public String batchSetStatus(@RequestParam String accountsJson) {
        // 漏洞点：反序列化未经验证的JSON数组
        List<Account> accounts = JSON.parseArray(accountsJson, Account.class);
        return accountService.batchUpdateStatus(accounts);
    }
}

class Account implements Serializable {
    private String id;
    private String username;
    private String token;
    private int status;
    
    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    
    public int getStatus() { return status; }
    public void setStatus(int status) { this.status = status; }
}

class AccountService {
    public String createAccount(Account account) {
        // 模拟数据库操作
        return "Account created: " + account.getUsername();
    }

    public String modifyAccount(Account account) {
        // 模拟更新操作
        return "Account modified: " + account.getId();
    }

    public String batchUpdateStatus(List<Account> accounts) {
        // 模拟批量操作
        return "Updated " + accounts.size() + " accounts";
    }
}