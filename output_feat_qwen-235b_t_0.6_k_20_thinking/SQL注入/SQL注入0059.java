package com.bank.demo.account;

import org.apache.ibatis.annotations.Param;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    @Autowired
    private IAccountService accountService;

    @GetMapping
    public List<Account> getAccounts(@RequestParam String orderField) {
        return accountService.listAccounts(orderField);
    }
}

interface IAccountService {
    List<Account> listAccounts(String orderField);
}

@Service
class AccountServiceImpl implements IAccountService {
    @Autowired
    private AccountMapper accountMapper;

    @Override
    public List<Account> listAccounts(String orderField) {
        return accountMapper.selectAccounts(orderField);
    }
}

interface AccountMapper extends BaseMapper<Account> {
    List<Account> selectAccounts(@Param("orderField") String orderField);
}

@TableName("accounts")
class Account {
    private Long id;
    private String accountNumber;
    private Double balance;
    // Getters and setters
}

// MyBatis XML Mapper
/*
<select id="selectAccounts" resultType="Account">
    SELECT * FROM accounts
    ORDER BY ${orderField}  <!-- Vulnerable to SQL Injection -->
</select>
*/

// Vulnerable Scenario:
// Attack payload example: 
// orderField=balance DESC; DROP TABLE accounts-- 
// This would first sort by balance descending, then drop the accounts table
// Another example: 
// orderField=name; EXEC xp_cmdshell('net user hacker Password123 /add')-- 
// (In SQL Server environments) to execute arbitrary OS commands