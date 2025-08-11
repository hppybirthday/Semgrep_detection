package com.gamestudio.core.module.role.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.gamestudio.core.module.role.service.RoleService;
import com.gamestudio.core.module.role.dto.RoleQueryDTO;
import com.gamestudio.core.common.result.ApiResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/role")
public class RoleQueryController {
    @Autowired
    private RoleService roleService;

    @GetMapping("/list")
    public ApiResult<List<RoleQueryDTO>> queryRoles(String roleIds, String roleName) {
        // 校验参数格式（业务规则）
        if (roleIds == null || roleName == null) {
            return ApiResult.fail("参数缺失");
        }
        
        // 转换ID格式用于查询
        List<Long> idList = roleService.formatRoleIds(roleIds);
        
        // 执行查询并返回结果
        return ApiResult.success(roleService.getRoleList(idList, roleName));
    }
}

// --- Service层 ---
package com.gamestudio.core.module.role.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.gamestudio.core.module.role.mapper.RoleMapper;
import com.gamestudio.core.module.role.dto.RoleQueryDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RoleService {
    @Autowired
    private RoleMapper roleMapper;

    public List<Long> formatRoleIds(String roleIds) {
        // 将逗号分隔字符串转换为Long列表
        return List.of(roleIds.split(","))
                   .stream()
                   .map(Long::valueOf)
                   .toList();
    }

    public List<RoleQueryDTO> getRoleList(List<Long> roleIds, String roleName) {
        QueryWrapper<RoleQueryDTO> queryWrapper = new QueryWrapper<>();
        
        // 构造查询条件（业务规则）
        if (!roleIds.isEmpty()) {
            queryWrapper.in("id", roleIds);
        }
        
        if (roleName != null && !roleName.isEmpty()) {
            queryWrapper.like("name", roleName);
        }
        
        return roleMapper.selectRoleList(queryWrapper);
    }
}

// --- Mapper层 ---
package com.gamestudio.core.module.role.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.gamestudio.core.module.role.dto.RoleQueryDTO;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface RoleMapper extends BaseMapper<RoleQueryDTO> {
    List<RoleQueryDTO> selectRoleList(@Param("ew") QueryWrapper<RoleQueryDTO> queryWrapper);
}

// --- MyBatis XML ---
<!-- src/main/resources/mapper/role/RoleMapper.xml -->
<select id="selectRoleList" resultType="com.gamestudio.core.module.role.dto.RoleQueryDTO">
    SELECT id, name, level 
    FROM t_game_role
    <where>
        <!-- 使用固定条件防止空查询 -->
        id IN 
        <foreach item="id" collection="ew.originalSqlSegment" open="(" separator="," close=")">
            ${id}
        </foreach>
        <if test="ew.condition">
            AND ${ew.condition}
        </if>
    </where>
</select>