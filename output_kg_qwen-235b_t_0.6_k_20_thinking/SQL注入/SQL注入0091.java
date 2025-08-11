package com.bank.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Controller
public class AccountController {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/account/details")
    @ResponseBody
    public List<Map<String, Object>> getAccountDetails(@RequestParam String accountId) {
        // 存在SQL注入漏洞的查询
        String query = "SELECT * FROM accounts WHERE account_id = '" + accountId + "' AND status = 'active'";
        
        // 模拟业务逻辑中复杂的查询处理
        List<Map<String, Object>> result = new ArrayList<>();
        try {
            result = jdbcTemplate.queryForList(query);
        } catch (Exception e) {
            // 隐藏错误细节（可能暴露更多攻击面）
            System.out.println("查询异常");
        }
        return result;
    }

    // 真实业务中可能存在的其他安全措施（但被错误绕过）
    private boolean validateAccountId(String id) {
        // 错误的验证逻辑（无法阻止常见注入攻击）
        return id != null && id.matches("[0-9]{6}(-[A-Z])\\?");
    }

    // 更复杂的查询示例（展示更多攻击面）
    @GetMapping("/account/transactions")
    @ResponseBody
    public List<Map<String, Object>> getAccountTransactions(
            @RequestParam String accountId,
            @RequestParam(required = false) String filter) {
        
        String baseQuery = "SELECT * FROM transactions WHERE account_id = '" + accountId + "'";
        if (filter != null && !filter.isEmpty()) {
            baseQuery += " AND type = '" + filter + "'";
        }
        // 按时间排序（可能被注入篡改）
        baseQuery += " ORDER BY transaction_date DESC";
        
        return jdbcTemplate.queryForList(baseQuery);
    }

    // 本应存在的安全查询方式（被错误注释）
    /*
    @GetMapping("/safe/account/details")
    @ResponseBody
    public List<Map<String, Object>> getSafeAccountDetails(@RequestParam String accountId) {
        String query = "SELECT * FROM accounts WHERE account_id = ? AND status = 'active'";
        return jdbcTemplate.queryForList(query, accountId);
    }
    */
}

// 数据库表结构模拟
/*
CREATE TABLE accounts (
    account_id VARCHAR(20) PRIMARY KEY,
    customer_name VARCHAR(100),
    balance DECIMAL(15,2),
    status VARCHAR(10)
);

CREATE TABLE transactions (
    transaction_id VARCHAR(36) PRIMARY KEY,
    account_id VARCHAR(20),
    amount DECIMAL(15,2),
    type VARCHAR(20),
    transaction_date TIMESTAMP
);
*/