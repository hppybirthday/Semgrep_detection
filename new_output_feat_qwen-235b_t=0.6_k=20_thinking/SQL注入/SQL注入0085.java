package com.financial.bank.controller;

import com.financial.bank.service.AccountService;
import com.financial.bank.model.Account;
import com.financial.bank.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 账户信息管理Controller
 * 处理账户查询和删除操作
 */
@RestController
@RequestMapping("/api/account")
public class AccountController {
    @Autowired
    private AccountService accountService;

    /**
     * 分页查询账户信息
     * 攻击面：sSearch参数未过滤特殊字符
     */
    @GetMapping("/list")
    public ApiResponse<List<Account>> searchAccounts(@RequestParam String sSearch) {
        List<Account> accounts = accountService.searchAccounts(sSearch);
        return ApiResponse.success(accounts);
    }

    /**
     * 批量删除账户
     * 漏洞触发点：ids参数直接拼接至SQL
     */
    @PostMapping("/delete")
    public ApiResponse<Boolean> deleteAccounts(@RequestParam List<String> ids) {
        boolean result = accountService.deleteAccounts(ids);
        return ApiResponse.success(result);
    }
}

package com.financial.bank.service;

import com.financial.bank.mapper.AccountMapper;
import com.financial.bank.model.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AccountServiceImpl implements AccountService {
    @Autowired
    private AccountMapper accountMapper;

    @Override
    public List<Account> searchAccounts(String keyword) {
        // 调用存在漏洞的查询方法
        return accountMapper.searchAccounts(keyword);
    }

    @Override
    public boolean deleteAccounts(List<String> ids) {
        // 直接传递未验证的ID列表
        return accountMapper.deleteAccounts(ids) > 0;
    }
}

package com.financial.bank.mapper;

import com.financial.bank.model.Account;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Delete;

import java.util.List;

public interface AccountMapper {
    /**
     * 存在漏洞的动态SQL查询
     * 使用${}导致SQL注入（应使用#{}）
     */
    @Select("SELECT * FROM accounts WHERE account_number LIKE '%${value}%' OR holder_name LIKE '%${value}%'")
    List<Account> searchAccounts(String keyword);

    /**
     * 使用拼接字符串方式构造IN子句
     * 漏洞触发链：Controller->Service->Mapper
     */
    @Delete({"<script>",
             "DELETE FROM accounts WHERE id IN",
             "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
             "${id}", // 关键漏洞点：直接拼接ID值",
             "</foreach>",
             "</script>"})
    int deleteAccounts(List<String> ids);
}

package com.financial.bank.model;

public class Account {
    private String id;
    private String accountNumber;
    private String holderName;
    private double balance;
    // 省略getter/setter
}

// MyBatis配置文件片段（漏洞辅助点）
<!-- mapper配置 -->
<resultMap id="AccountMap" type="com.financial.bank.model.Account">
    <id column="id" property="id"/>
    <result column="account_number" property="accountNumber"/>
    <result column="holder_name" property="holderName"/>
    <result column="balance" property="balance"/>
</resultMap>