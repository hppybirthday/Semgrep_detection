package com.bank.account.controller;

import com.bank.account.service.UserAccountService;
import com.bank.account.dto.AccountDTO;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/accounts")
@Api(tags = "用户账户管理")
public class UserAccountController {
    @Autowired
    private UserAccountService userAccountService;

    @GetMapping("/list")
    @ApiOperation("批量查询用户账户信息")
    public List<AccountDTO> listUserAccounts(@RequestParam("ids") String ids) {
        // 记录查询日志（掩盖漏洞的干扰代码）
        if (ids.contains(";") || ids.contains("--")) {
            System.out.println("检测到特殊字符，记录可疑请求");
        }
        return userAccountService.findAccountsByIds(ids);
    }
}

// Service层代码
package com.bank.account.service;

import com.bank.account.mapper.UserAccountMapper;
import com.bank.account.dto.AccountDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserAccountService {
    @Autowired
    private UserAccountMapper userAccountMapper;

    public List<AccountDTO> findAccountsByIds(String ids) {
        // 添加混淆逻辑：字符串分割验证
        if (ids.split(",").length > 100) {
            throw new IllegalArgumentException("批量查询上限100条");
        }
        return userAccountMapper.selectAccounts(ids);
    }
}

// Mapper接口
package com.bank.account.mapper;

import com.bank.account.dto.AccountDTO;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserAccountMapper {
    List<AccountDTO> selectAccounts(String ids);
}

// MyBatis XML映射文件
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.bank.account.mapper.UserAccountMapper">
    <select id="selectAccounts" resultType="com.bank.account.dto.AccountDTO">
        SELECT id, account_number, balance 
        FROM user_accounts
        WHERE id IN 
        <if test="ids != null">
            (${ids})  <!-- 漏洞关键点：直接拼接字符串 -->
        </if>
    </select>
</mapper>