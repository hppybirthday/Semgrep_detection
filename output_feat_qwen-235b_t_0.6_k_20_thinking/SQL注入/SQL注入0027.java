package com.bank.account;

import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/accounts")
public class AccountController {
    @Autowired
    private AccountService accountService;

    @GetMapping("/query")
    public List<Account> getAccountByMainId(@RequestParam String mainId) {
        return accountService.findAccountByMainId(mainId);
    }
}

@Service
class AccountService {
    @Autowired
    private AccountMapper accountMapper;

    public List<Account> findAccountByMainId(String mainId) {
        return accountMapper.selectByMainId(mainId);
    }
}

@Mapper
interface AccountMapper extends BaseMapper<Account> {
    List<Account> selectByMainId(String mainId);
}

@Data
class Account {
    private String mainId;
    private String accountNumber;
    private Double balance;
    private String userId;
}

// MyBatis XML Mapper
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.bank.account.AccountMapper">
    <select id="selectByMainId" resultType="com.bank.account.Account">
        SELECT * FROM account WHERE main_id = ${mainId}
    </select>
</mapper>