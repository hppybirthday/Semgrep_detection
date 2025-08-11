package com.example.bank.mapper;

import com.example.bank.entity.Account;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface AccountMapper {
    @Delete("DELETE FROM accounts WHERE id IN (${ids})")
    void deleteAccountsByIds(@Param("ids") String ids);
}

// Controller层示例
package com.example.bank.controller;

import com.example.bank.mapper.AccountMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/accounts")
public class AccountController {
    @Autowired
    private AccountMapper accountMapper;

    @DeleteMapping("/delete")
    public String deleteAccounts(@RequestParam String ids) {
        // 直接传递未经验证的参数到Mapper
        accountMapper.deleteAccountsByIds(ids);
        return "Deleted accounts with IDs: " + ids;
    }
}

// XML映射文件（实际项目中可能与注解混用）
<!-- resources/mapper/AccountMapper.xml -->
<mapper namespace="com.example.bank.mapper.AccountMapper">
    <delete id="deleteAccountsByIds">
        DELETE FROM accounts
        WHERE id IN (${ids})
    </delete>
</mapper>

// 实体类
package com.example.bank.entity;

public class Account {
    private Long id;
    private String accountNumber;
    private Double balance;
    // 省略getter/setter
}