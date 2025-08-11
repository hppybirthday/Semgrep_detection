package com.bank.financial.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.bank.financial.dao.AccountMapper;
import com.bank.financial.model.Account;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;

@Service
public class AccountService extends ServiceImpl<AccountMapper, Account> {
    // 根据用户ID和用户名查询账户信息（包含排序参数）
    public List<Account> getAccounts(String userId, String username, String order) {
        if (!StringUtils.hasText(userId) || !StringUtils.hasText(username)) {
            return List.of();
        }
        
        // 构造查询条件
        QueryWrapper<Account> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("user_id", userId)
                    .like("username", username);
                    
        // 动态排序处理
        if (StringUtils.hasText(order)) {
            queryWrapper.orderBy(true, true, "ORDER BY " + order);
        }
        
        return this.list(queryWrapper);
    }
}