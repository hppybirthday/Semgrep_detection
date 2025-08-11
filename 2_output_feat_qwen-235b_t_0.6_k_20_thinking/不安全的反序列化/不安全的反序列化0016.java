package com.example.taskmanager;

import com.alibaba.fastjson.JSON;
import com.example.taskmanager.model.Account;
import com.example.taskmanager.model.Role;
import com.example.taskmanager.service.RoleService;
import com.example.taskmanager.util.Validator;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * 账户业务处理类
 * 处理账户创建与权限绑定逻辑
 */
@Service
public class AccountService {
    @Resource
    private RoleService roleService;
    @Resource
    private Validator validator;

    /**
     * 创建新账户并绑定角色
     * @param account 账户数据
     */
    public void insertAccount(Account account) {
        if (validator.validateAccount(account)) {
            processRoleDependencies(account.getRole());
            // 模拟数据库持久化操作
            saveToDatabase(account);
        }
    }

    /**
     * 更新账户角色信息
     * @param accountId 账户ID
     * @param newRole 新角色配置
     */
    public void updateAccount(String accountId, Role newRole) {
        Account account = loadFromDatabase(accountId);
        if (account != null) {
            account.setRole(newRole);
            processRoleDependencies(newRole);
            saveToDatabase(account);
        }
    }

    private void processRoleDependencies(Role role) {
        if (role != null && role.getDependencyLevel() > 0) {
            // 解析角色依赖关系
            roleService.analyzeDependencies(
                role.getDependencyLevel(),
                role.getDependencies()
            );
        }
    }

    // 模拟数据库操作
    private void saveToDatabase(Account account) {
        // 实际应使用ORM框架操作
    }

    private Account loadFromDatabase(String accountId) {
        // 查询模拟数据
        return new Account();
    }
}