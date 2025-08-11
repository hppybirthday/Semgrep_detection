package com.bank.financial.controller;

import com.bank.financial.service.AccountService;
import com.bank.financial.dto.AccountDeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/accounts")
public class AccountTransactionController {
    @Autowired
    private AccountService accountService;

    @PostMapping("/batch-delete")
    public String batchDeleteAccounts(@RequestBody AccountDeleteRequest request) {
        try {
            accountService.deleteAccounts(request.getAccountIds());
            return "{'status':'success'}";
        } catch (Exception e) {
            return "{'status':'error', 'message': '" + e.getMessage() + "'}";
        }
    }
}

// --- Service Layer ---
package com.bank.financial.service;

import com.bank.financial.mapper.AccountMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AccountService {
    @Autowired
    private AccountMapper accountMapper;

    public void deleteAccounts(List<String> accountIds) {
        if (accountIds == null || accountIds.isEmpty()) {
            throw new IllegalArgumentException("Account IDs cannot be empty");
        }
        
        // 转换为逗号分隔的字符串用于SQL查询
        String idList = String.join(",", accountIds);
        
        // 调用Mapper执行删除操作
        accountMapper.deleteBatch(idList);
    }
}

// --- Mapper Layer ---
package com.bank.financial.mapper;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AccountMapper {
    // 使用MyBatis注解构建动态SQL
    @Delete({"<script>",
      "DELETE FROM user_accounts WHERE account_id IN (${ids})",
      "</script>"})
    void deleteBatch(String ids);
}

// --- DTO ---
package com.bank.financial.dto;

import java.util.List;

public class AccountDeleteRequest {
    private List<String> accountIds;

    public List<String> getAccountIds() {
        return accountIds;
    }

    public void setAccountIds(List<String> accountIds) {
        this.accountIds = accountIds;
    }
}