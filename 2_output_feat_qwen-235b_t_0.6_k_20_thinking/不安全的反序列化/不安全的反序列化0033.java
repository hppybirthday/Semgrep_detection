package com.gamestudio.admin.controller;

import com.gamestudio.admin.dto.RoleBatchSetStatusDTO;
import com.gamestudio.admin.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/role")
public class RoleController {
    @Autowired
    private RoleService roleService;

    /**
     * 批量设置角色状态（启用/禁用）
     * @param dto 请求参数
     */
    @PostMapping("/batch-set-status")
    public void batchSetRoleStatus(@RequestBody RoleBatchSetStatusDTO dto) {
        List<String> roleIds = dto.getRoleIds();
        Integer status = dto.getStatus();
        
        for (String roleId : roleIds) {
            // 异步处理避免阻塞主线程
            new Thread(() -> roleService.processRoleStatus(roleId, status)).start();
        }
    }
}

package com.gamestudio.admin.dto;

import java.util.List;

public class RoleBatchSetStatusDTO {
    private List<String> roleIds;
    private Integer status;

    public List<String> getRoleIds() {
        return roleIds;
    }

    public void setRoleIds(List<String> roleIds) {
        this.roleIds = roleIds;
    }

    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }
}

package com.gamestudio.admin.service;

import com.gamestudio.admin.cache.RoleCacheManager;
import com.gamestudio.admin.model.RoleDependencies;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RoleService {
    @Autowired
    private RoleCacheManager roleCacheManager;

    /**
     * 处理角色状态变更逻辑
     * @param roleId 角色ID
     * @param status 新状态
     */
    public void processRoleStatus(String roleId, Integer status) {
        // 获取角色依赖信息（存在漏洞点）
        RoleDependencies dependencies = roleCacheManager.getRoleDependencies(roleId);
        
        if (dependencies != null && validateDependencies(dependencies)) {
            // 更新角色状态到数据库
            updateRoleStatusInDB(roleId, status);
            // 清理缓存
            roleCacheManager.clearRoleCache(roleId);
        }
    }

    private boolean validateDependencies(RoleDependencies dependencies) {
        // 简单校验依赖关系有效性
        return dependencies.getRequiredResources() != null && 
               dependencies.getRequiredResources().size() > 0;
    }

    private void updateRoleStatusInDB(String roleId, Integer status) {
        // 模拟数据库更新操作
    }
}

package com.gamestudio.admin.cache;

import com.gamestudio.admin.model.RoleDependencies;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RoleCacheManager {
    private final RedisTemplate<String, Object> redisTemplate;

    public RoleCacheManager(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 获取角色依赖信息
     * @param roleId 角色ID
     * @return 依赖信息
     */
    public RoleDependencies getRoleDependencies(String roleId) {
        String cacheKey = buildRoleDependenciesKey(roleId);
        
        // 从Redis获取序列化数据（漏洞触发点）
        return (RoleDependencies) redisTemplate.opsForValue().get(cacheKey);
    }

    /**
     * 构建角色依赖缓存键
     * @param roleId 角色ID
     * @return 缓存键
     */
    private String buildRoleDependenciesKey(String roleId) {
        return String.format("role.role-dependencies.%s", roleId);
    }

    /**
     * 清理角色缓存
     * @param roleId 角色ID
     */
    public void clearRoleCache(String roleId) {
        String cacheKey = buildRoleDependenciesKey(roleId);
        redisTemplate.delete(cacheKey);
    }
}

package com.gamestudio.admin.model;

import java.util.List;

public class RoleDependencies {
    private List<String> requiredResources;
    private List<String> compatiblePlugins;

    public List<String> getRequiredResources() {
        return requiredResources;
    }

    public void setRequiredResources(List<String> requiredResources) {
        this.requiredResources = requiredResources;
    }

    public List<String> getCompatiblePlugins() {
        return compatiblePlugins;
    }

    public void setCompatiblePlugins(List<String> compatiblePlugins) {
        this.compatiblePlugins = compatiblePlugins;
    }
}