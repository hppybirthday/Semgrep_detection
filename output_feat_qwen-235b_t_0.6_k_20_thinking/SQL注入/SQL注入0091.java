package com.example.bank.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.bank.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/accounts")
public class AccountController {
    @Autowired
    private AccountService accountService;

    @GetMapping("/list")
    public Page<Account> getAccounts(@RequestParam("pageNum") int pageNum,
                                     @RequestParam("pageSize") int pageSize,
                                     @RequestParam(value = "orderBy", required = false) String orderBy) {
        return accountService.getAccounts(pageNum, pageSize, orderBy);
    }
}

package com.example.bank.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.bank.mapper.AccountMapper;
import com.example.bank.model.Account;
import org.springframework.stereotype.Service;

@Service
public class AccountService extends ServiceImpl<AccountMapper, Account> {
    public Page<Account> getAccounts(int pageNum, int pageSize, String orderBy) {
        Page<Account> page = new Page<>(pageNum, pageSize);
        String orderClause = orderBy != null ? orderBy : "account_number";
        return query().orderBy(true, orderClause).page(page);
    }
}

package com.example.bank.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.bank.model.Account;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AccountMapper extends BaseMapper<Account> {}

// MyBatis XML 配置
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.bank.mapper.AccountMapper">
  <select id="selectPage" resultType="com.example.bank.model.Account">
    SELECT * FROM accounts
    <if test="ew != null and ew.orderBy != null">
      ORDER BY ${ew.orderBy}
    </if>
  </select>
</mapper>