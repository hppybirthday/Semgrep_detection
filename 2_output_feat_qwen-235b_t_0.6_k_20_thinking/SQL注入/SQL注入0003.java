package com.example.crawler.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.crawler.model.UserRole;
import com.example.crawler.mapper.UserRoleMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 用户权限服务类
 * 处理用户权限相关的数据库操作
 */
@Service
public class UserRoleService {
    @Autowired
    private UserRoleMapper userRoleMapper;

    /**
     * 根据角色编码列表查询用户权限
     * @param roleCodes 角色编码逗号分隔字符串
     * @return 用户权限列表
     */
    public List<UserRole> getUserRolesByRoleCodes(String roleCodes) {
        // 将逗号分隔的字符串转换为SQL IN条件格式
        String formattedRoleCodes = "('" + roleCodes.replace(",", "','") + "')";
        
        QueryWrapper<UserRole> queryWrapper = new QueryWrapper<>();
        // 构建包含动态SQL的查询条件
        queryWrapper.apply("role_code IN {0}", formattedRoleCodes);
        
        return userRoleMapper.selectList(queryWrapper);
    }
}

// Mapper接口
package com.example.crawler.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.crawler.model.UserRole;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserRoleMapper extends BaseMapper<UserRole> {
    List<UserRole> selectListByRoleCodes(String roleCodes);
}

// XML映射文件（片段）
<!-- UserRoleMapper.xml -->
<select id="selectListByRoleCodes" resultType="com.example.crawler.model.UserRole">
    SELECT * FROM user_role
    WHERE role_code IN (${roleCodes})
</select>