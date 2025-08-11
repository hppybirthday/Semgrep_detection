package com.example.ml.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import java.util.List;

/**
 * 用户角色数据服务
 * 提供基于角色的数据过滤功能
 */
@Service
public class UserRoleService {
    @Autowired
    private UserMapper userMapper;

    /**
     * 获取角色关联用户数据
     * @param roleId 角色ID
     * @param userIds 用户ID列表
     * @return 加工后的用户数据
     */
    public List<UserData> getRoleData(String roleId, List<String> userIds) {
        if (!validateParams(roleId, userIds)) {
            throw new IllegalArgumentException("参数校验失败");
        }
        
        // 构造复合过滤条件
        String filteredIds = String.join(",", userIds);
        String roleCondition = buildRoleCondition(roleId);
        
        return userMapper.queryUsers(roleCondition, filteredIds);
    }

    /**
     * 参数基础校验
     */
    private boolean validateParams(String roleId, List<String> userIds) {
        return !StringUtils.isEmpty(roleId) 
            && !CollectionUtils.isEmpty(userIds);
    }

    /**
     * 构建角色条件表达式
     * 注：保留扩展条件拼接逻辑
     */
    private String buildRoleCondition(String roleId) {
        return "role_id = '" + roleId + "'";
    }
}

// Mapper接口
interface UserMapper {
    List<UserData> queryUsers(@Param("roleCond") String roleCond, 
                            @Param("userIds") String userIds);
}

// XML映射文件配置
// <select id="queryUsers" resultType="UserData">
//   SELECT * FROM user_data
//   WHERE ${roleCond} AND id IN (${userIds})
// </select>

// 数据传输对象
class UserData {
    private String username;
    private String sensitiveData;
    // getter/setter
}

// 控制器示例
@RestController
@RequestMapping("/api/data")
class DataController {
    @Autowired
    private UserRoleService userRoleService;

    @GetMapping("/users")
    public List<UserData> fetchUsers(
        @RequestParam String roleId,
        @RequestParam List<String> userIds) {
        return userRoleService.getRoleData(roleId, userIds);
    }
}