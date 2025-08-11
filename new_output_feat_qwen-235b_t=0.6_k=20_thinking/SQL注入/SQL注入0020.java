package com.example.security.controller;

import com.example.security.service.RoleService;
import com.example.security.dto.RoleAssignDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/roles")
public class RoleController {
    @Autowired
    private RoleService roleService;

    @PostMapping("/assign")
    public String assignRoles(@RequestBody RoleAssignDTO dto) {
        if (dto.getUserIds() == null || dto.getRoleCodes() == null) {
            return "Invalid input";
        }
        
        // 将角色代码字符串传递给服务层
        roleService.updateUserRoles(dto.getUserIds(), dto.getRoleCodes());
        return "Roles assigned successfully";
    }
}

package com.example.security.service;

import com.example.security.dao.RoleDao;
import com.example.security.dto.RoleAssignDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RoleService {
    @Autowired
    private RoleDao roleDao;

    public void updateUserRoles(List<Long> userIds, String roleCodes) {
        // 未对roleCodes进行任何过滤或参数化处理
        roleDao.batchUpdateRoles(userIds, roleCodes);
    }
}

package com.example.security.dao;

import org.beetl.sql.annotation.entity.SqlStatement;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class RoleDao {
    @Autowired
    private SQLManager sqlManager;

    // 使用字符串拼接方式构建动态SQL
    @SqlStatement(params = "userIds,roleCodes")
    public void batchUpdateRoles(List<Long> userIds, String roleCodes) {
        // 构造包含IN子句的SQL语句
        String sql = "UPDATE user_roles SET role_code IN (" + roleCodes + ") WHERE user_id IN (";
        
        // 构造用户ID的IN列表
        for (int i = 0; i < userIds.size(); i++) {
            sql += userIds.get(i);
            if (i < userIds.size() - 1) {
                sql += ",";
            }
        }
        sql += ")";
        
        // 执行拼接后的SQL
        sqlManager.execute(sql);
    }
}

package com.example.security.dto;

import java.util.List;

public class RoleAssignDTO {
    private List<Long> userIds;
    private String roleCodes;

    public List<Long> getUserIds() {
        return userIds;
    }

    public void setUserIds(List<Long> userIds) {
        this.userIds = userIds;
    }

    public String getRoleCodes() {
        return roleCodes;
    }

    public void setRoleCodes(String roleCodes) {
        this.roleCodes = roleCodes;
    }
}