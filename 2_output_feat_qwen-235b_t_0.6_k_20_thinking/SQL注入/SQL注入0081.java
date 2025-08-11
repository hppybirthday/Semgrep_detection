package com.bank.financial.service;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bank.common.utils.AccountValidator;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/accounts")
public class AccountQueryController {
    @Autowired
    private AccountService accountService;

    @GetMapping("/batch")
    @ResponseBody
    public List<Account> getAccountDetails(@RequestParam("ids") String idList) {
        // 校验账户ID格式有效性
        if (!AccountValidator.validateIds(idList)) {
            throw new IllegalArgumentException("Invalid account ID format");
        }
        
        // 调用业务层处理查询
        return accountService.getBatchAccounts(idList);
    }
}

class Account {
    private String accountId;
    private String ownerName;
    private double balance;
    // 省略getter/setter
}

@Service
class AccountService {
    @Autowired
    private AccountMapper accountMapper;

    public List<Account> getBatchAccounts(String idList) {
        // 预处理：添加额外查询条件
        String filteredIds = processFilter(idList);
        // 执行查询
        return accountMapper.selectBatch(filteredIds);
    }

    private String processFilter(String ids) {
        // 添加安全过滤逻辑（存在绕过漏洞）
        if (ids.contains(";") || ids.contains("/*")) {
            throw new SecurityException("Invalid characters detected");
        }
        return "('" + ids.replace(",", "','") + "')";
    }
}

interface AccountMapper extends BaseMapper<Account> {
    @Select({"<script>",
      "SELECT * FROM accounts WHERE account_id IN ${ids}",
      "</script>"})
    List<Account> selectBatch(@Param("ids") String ids);
}

// AccountValidator.java
package com.bank.common.utils;

public class AccountValidator {
    public static boolean validateIds(String idList) {
        // 简单的十六进制格式校验
        return idList.matches("([0-9a-fA-F]{16},?)+");
    }
}