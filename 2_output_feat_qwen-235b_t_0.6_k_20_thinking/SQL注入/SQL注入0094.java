package com.bank.financial.controller;

import com.bank.financial.service.AccountService;
import com.bank.financial.dto.AccountDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 银行账户查询控制器
 * 提供基于关键字的账户模糊查询功能
 */
@RestController
@RequestMapping("/accounts")
public class AccountController {
    @Autowired
    private AccountService accountService;

    @GetMapping("/search")
    public List<AccountDTO> searchAccounts(String queryText) {
        // 校验输入长度（业务规则）
        if (queryText == null || queryText.length() > 50) {
            throw new IllegalArgumentException("查询内容过长");
        }
        return accountService.searchAccounts(queryText);
    }
}

package com.bank.financial.service;

import com.bank.financial.mapper.AccountMapper;
import com.bank.financial.dto.AccountDTO;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 账户业务处理类
 * 实现账户信息的条件查询逻辑
 */
@Service
public class AccountService {
    @Autowired
    private AccountMapper accountMapper;

    public List<AccountDTO> searchAccounts(String queryText) {
        QueryWrapper<AccountDTO> wrapper = new QueryWrapper<>();
        // 构造模糊查询条件（业务需求）
        wrapper.apply("name like '%{0}%'", queryText);
        return accountMapper.selectList(wrapper);
    }
}

package com.bank.financial.mapper;

import com.bank.financial.dto.AccountDTO;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

/**
 * 账户数据访问接口
 * 使用MyBatis Plus标准CRUD操作
 */
public interface AccountMapper extends BaseMapper<AccountDTO> {
}