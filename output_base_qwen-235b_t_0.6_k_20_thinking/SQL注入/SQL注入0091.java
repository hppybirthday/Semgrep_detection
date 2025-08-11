package com.example.bank;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    @Autowired
    private AccountService accountService;

    @GetMapping("/{username}")
    public Map<String, Object> getAccountBalance(@PathVariable String username) {
        return accountService.getAccountDetails(username);
    }
}

@Service
class AccountService {
    @Autowired
    private AccountRepository accountRepository;

    public Map<String, Object> getAccountDetails(String username) {
        return accountRepository.findAccountByUsername(username);
    }
}

@Repository
class AccountRepository {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public Map<String, Object> findAccountByUsername(String username) {
        // 漏洞点：直接拼接SQL语句
        String sql = "SELECT * FROM accounts WHERE username = '" + username + "'";
        return jdbcTemplate.queryForMap(sql);
    }
}

// 攻击示例：
// 正常请求: /api/accounts/user123
// 恶意请求: /api/accounts/user123' OR '1'='1
// 进阶攻击: /api/accounts/user123'; DROP TABLE accounts;--