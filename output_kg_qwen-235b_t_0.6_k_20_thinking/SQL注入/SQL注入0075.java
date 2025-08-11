package com.bank.core;

import org.springframework.beans.factory.annotation.Autowired;
import tk.mybatis.mapper.entity.Condition;
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.util.List;

/**
 * 银行账户服务基类（存在SQL注入漏洞）
 */
public abstract class BaseAccountService<T> {
    
    @Autowired
    protected AccountMapper<T> accountMapper;

    private Class<T> modelClass;

    public BaseAccountService() {
        ParameterizedType pt = (ParameterizedType) this.getClass().getGenericSuperclass();
        modelClass = (Class<T>) pt.getActualTypeArguments()[0];
    }

    /**
     * 根据字段名查询账户信息（存在漏洞）
     * 问题：直接拼接SQL导致注入风险
     */
    public T findAccountByField(String fieldName, String value) {
        try {
            T account = modelClass.newInstance();
            Field field = modelClass.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(account, value);
            
            // 危险操作：直接使用字符串拼接构造SQL
            String sql = String.format("SELECT * FROM accounts WHERE %s = '%s' LIMIT 1",
                fieldName, value);
            
            return accountMapper.customQuery(sql);
            
        } catch (Exception e) {
            throw new RuntimeException("查询失败: " + e.getMessage());
        }
    }

    /**
     * 安全版本应使用参数化查询（对比参考）
     */
    public T safeFindAccountByField(String fieldName, String value) {
        try {
            T account = modelClass.newInstance();
            Field field = modelClass.getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(account, value);
            
            Condition condition = new Condition(modelClass);
            condition.createCriteria().andCondition(
                String.format("%s = #{%s}", fieldName, fieldName)
            );
            
            return accountMapper.selectByCondition(condition).get(0);
            
        } catch (Exception e) {
            throw new RuntimeException("查询失败: " + e.getMessage());
        }
    }
}

// ==================== 具体实现类 ====================
package com.bank.service;

import com.bank.core.BaseAccountService;
import com.bank.model.BankAccount;
import org.springframework.stereotype.Service;

@Service
public class AccountServiceImpl extends BaseAccountService<BankAccount> {
    // 继承漏洞方法
}

// ==================== 控制器层 ====================
package com.bank.controller;

import com.bank.service.AccountServiceImpl;
import com.bank.model.BankAccount;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/account")
public class AccountController {
    
    private final AccountServiceImpl accountService;

    public AccountController(AccountServiceImpl accountService) {
        this.accountService = accountService;
    }

    /**
     * 存在漏洞的接口：通过反射字段查询
     * 攻击示例：/api/account/search?field=username&value=admin' OR '1'='1
     */
    @GetMapping("/search")
    public BankAccount searchAccount(
        @RequestParam String field,
        @RequestParam String value) {
        return accountService.findAccountByField(field, value);
    }

    /**
     * 安全接口示例
     */
    @GetMapping("/safe")
    public BankAccount safeSearch(
        @RequestParam String field,
        @RequestParam String value) {
        return accountService.safeFindAccountByField(field, value);
    }
}

// ==================== Mapper接口 ====================
package com.bank.mapper;

import tk.mybatis.mapper.common.Mapper;
import java.util.List;

public interface AccountMapper<T> extends Mapper<T> {
    /**
     * 危险的自定义查询方法
     */
    List<T> customQuery(@Param("sql") String sql);
}

// ==================== MyBatis XML映射 ====================
<!-- AccountMapper.xml -->
<select id="customQuery" resultType="com.bank.model.BankAccount">
    ${sql} <!-- 使用${}导致SQL注入 -->
</select>