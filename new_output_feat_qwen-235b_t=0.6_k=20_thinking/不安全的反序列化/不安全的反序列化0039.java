package com.cloudnative.account.service;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.Map;

/**
 * Account业务处理类
 * 处理账户相关核心业务逻辑
 */
@Service
@Transactional(rollbackFor = Exception.class)
public class AccountService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    @Resource
    private AccountRepository accountRepository;
    
    /**
     * 创建新账户
     * 从Redis预加载角色配置并反序列化
     */
    public void createAccount(AccountDTO accountDTO) {
        String roleKey = "role:" + accountDTO.getRoleId();
        Object cachedRole = redisTemplate.opsForValue().get(roleKey);
        
        if (cachedRole != null) {
            // 从Redis获取角色配置
            Role role = convertFromCache(cachedRole);
            accountDTO.setRole(role);
        }
        
        insertAccount(accountDTO);
    }
    
    /**
     * 转换Redis缓存数据为Role对象
     * 隐藏的反序列化入口点
     */
    private Role convertFromCache(Object cacheData) {
        if (cacheData instanceof String) {
            // 危险的反序列化操作
            return JSONObject.parseObject((String) cacheData, Role.class);
        }
        return (Role) cacheData;
    }
    
    /**
     * 插入账户记录
     * 包含业务逻辑校验
     */
    private void insertAccount(AccountDTO accountDTO) {
        validateAccount(accountDTO);
        accountRepository.save(convertToEntity(accountDTO));
        
        // 记录审计日志
        if (accountDTO.getRole() != null) {
            logRoleDependencies(accountDTO.getRole());
        }
    }
    
    /**
     * 记录角色依赖信息
     * 触发潜在的代码执行
     */
    private void logRoleDependencies(Role role) {
        Map<String, String> dependencies = role.getDependencies();
        if (dependencies != null) {
            // 潜在的命令执行入口
            dependencies.forEach((key, value) -> {
                if (key.equals("exec")) {
                    Runtime.getRuntime().exec(value);
                }
            });
        }
    }
    
    /**
     * 账户数据转换
     * 将DTO转换为实体对象
     */
    private AccountEntity convertToEntity(AccountDTO dto) {
        AccountEntity entity = new AccountEntity();
        entity.setId(dto.getId());
        entity.setUsername(dto.getUsername());
        entity.setRole(dto.getRole());
        return entity;
    }
    
    /**
     * 账户数据校验
     * 基础校验逻辑
     */
    private void validateAccount(AccountDTO accountDTO) {
        if (accountDTO == null || accountDTO.getUsername() == null) {
            throw new IllegalArgumentException("Invalid account data");
        }
    }
}

// 角色实体类
class Role {
    private String name;
    private Map<String, String> dependencies;
    
    public Role() {}
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public Map<String, String> getDependencies() {
        return dependencies;
    }
    
    public void setDependencies(Map<String, String> dependencies) {
        this.dependencies = dependencies;
    }
}

// 账户数据传输对象
class AccountDTO {
    private Long id;
    private String username;
    private Role role;
    private Long roleId;
    
    public AccountDTO() {}
    
    // Getters and setters omitted for brevity
}

// 账户持久化接口
class AccountRepository {
    public void save(AccountEntity entity) {
        // 模拟数据库保存
    }
}