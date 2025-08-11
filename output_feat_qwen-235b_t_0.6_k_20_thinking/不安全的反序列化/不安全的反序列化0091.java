package com.example.bank.controller;

import com.alibaba.fastjson.JSONObject;
import com.example.bank.service.AccountService;
import com.example.bank.model.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    
    @Autowired
    private AccountService accountService;

    @PostMapping
    public String insertAccount(@RequestBody String jsonData) {
        // 漏洞点：直接反序列化不可信输入
        Account account = JSONObject.parseObject(jsonData, Account.class);
        return accountService.createAccount(account);
    }

    @PutMapping("/{id}")
    public String updateAccount(@PathVariable String id, @RequestBody String jsonData) {
        // 漏洞点：未验证数据来源
        Account account = JSONObject.parseObject(jsonData, Account.class);
        account.setId(id);
        return accountService.updateAccount(account);
    }

    @GetMapping("/{id}")
    public Account getAccount(@PathVariable String id) {
        return accountService.getAccount(id);
    }
}

// Account实体类
package com.example.bank.model;

public class Account {
    private String id;
    private String owner;
    private double balance;
    private String currency;
    // getters/setters
}

// Service层
package com.example.bank.service;

import com.example.bank.model.Account;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class AccountService {
    private Map<String, Account> accounts = new HashMap<>();

    public String createAccount(Account account) {
        accounts.put(account.getId(), account);
        return "Account created: " + account.getId();
    }

    public String updateAccount(Account account) {
        if(accounts.containsKey(account.getId())) {
            accounts.put(account.getId(), account);
            return "Account updated: " + account.getId();
        }
        return "Account not found";
    }

    public Account getAccount(String id) {
        return accounts.get(id);
    }
}