package com.gamestudio.desktop.controller;

import com.gamestudio.desktop.service.RoleService;
import com.gamestudio.desktop.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 角色管理控制器
 * 处理角色相关操作
 */
@RestController
@RequestMapping("/api/roles")
public class RoleController {
    @Autowired
    private RoleService roleService;

    /**
     * 批量删除角色
     * @param roleCodes 角色编码列表
     * @return 操作结果
     */
    @DeleteMapping("/batch")
    public Result<Boolean> deleteRoles(@RequestParam("roleCodes") List<String> roleCodes) {
        if (roleCodes == null || roleCodes.isEmpty()) {
            return Result.error("角色编码不能为空");
        }
        
        // 记录日志但未进行安全校验
        System.out.println("开始删除角色: " + roleCodes);
        
        try {
            boolean result = roleService.removeRolesByRoleCodes(roleCodes);
            return Result.success(result);
        } catch (Exception e) {
            return Result.error("删除角色失败: " + e.getMessage());
        }
    }
}

package com.gamestudio.desktop.service;

import com.gamestudio.desktop.mapper.RoleMapper;
import com.gamestudio.desktop.model.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 角色服务类
 * 处理角色业务逻辑
 */
@Service
public class RoleService {
    @Autowired
    private RoleMapper roleMapper;

    /**
     * 根据角色编码批量删除
     * @param roleCodes 角色编码列表
     * @return 删除结果
     */
    public boolean removeRolesByRoleCodes(List<String> roleCodes) {
        if (roleCodes == null || roleCodes.isEmpty()) {
            return false;
        }
        
        // 构建查询条件
        String condition = buildCondition(roleCodes);
        
        // 执行删除操作
        return roleMapper.deleteByCustomCondition(condition) > 0;
    }
    
    /**
     * 构建SQL查询条件
     * @param roleCodes 角色编码列表
     * @return SQL条件字符串
     */
    private String buildCondition(List<String> roleCodes) {
        StringBuilder conditionBuilder = new StringBuilder("role_code IN (");
        
        for (int i = 0; i < roleCodes.size(); i++) {
            if (i > 0) {
                conditionBuilder.append(",");
            }
            // 直接拼接用户输入
            conditionBuilder.append("'").append(roleCodes.get(i)).append("'");
        }
        
        conditionBuilder.append(")");
        return conditionBuilder.toString();
    }
}

package com.gamestudio.desktop.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 角色数据访问接口
 */
@Repository
public interface RoleMapper {
    /**
     * 自定义条件删除
     * @param condition SQL条件字符串
     * @return 影响记录数
     */
    @Select({"<script>",
             "DELETE FROM role WHERE ${condition}",
             "</script>"})
    int deleteByCustomCondition(@Param("condition") String condition);
}

package com.gamestudio.desktop.model;

/**
 * 角色实体类
 */
public class Role {
    private Long id;
    private String roleName;
    private String roleCode;
    private String description;
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getRoleName() { return roleName; }
    public void setRoleName(String roleName) { this.roleName = roleName; }
    
    public String getRoleCode() { return roleCode; }
    public void setRoleCode(String roleCode) { this.roleCode = roleCode; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

package com.gamestudio.desktop.common;

/**
 * 通用响应结果类
 */
public class Result<T> {
    private boolean success;
    private String message;
    private T data;
    
    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.success = true;
        result.data = data;
        return result;
    }
    
    public static <T> Result<T> error(String message) {
        Result<T> result = new Result<>();
        result.success = false;
        result.message = message;
        return result;
    }
    
    // Getters and Setters
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public T getData() { return data; }
    public void setData(T data) { this.data = data; }
}