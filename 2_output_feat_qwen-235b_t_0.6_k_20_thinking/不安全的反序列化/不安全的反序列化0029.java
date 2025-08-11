package com.enterprise.auth.service;

import com.alibaba.fastjson.JSON;
import com.enterprise.cache.RedisCache;
import com.enterprise.excel.XLSReader;
import com.enterprise.role.model.Role;
import com.enterprise.utils.StringUtils;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * 角色服务实现类
 * 处理角色数据导入与缓存管理
 */
@Service
public class RoleServiceImpl {
    @Autowired
    private RedisCache redisCache;
    @Autowired
    private XLSReader xlsReader;

    /**
     * 导入角色Excel数据并缓存
     * @param filePath Excel文件路径
     */
    public void importExcel(String filePath) {
        List<Map<String, Object>> dataList = xlsReader.read(filePath);
        List<Role> roles = convertToRoles(dataList);
        cacheRoles(roles);
    }

    /**
     * 将Excel数据转换为角色对象列表
     * @param dataList 原始数据列表
     * @return 角色对象列表
     */
    private List<Role> convertToRoles(List<Map<String, Object>> dataList) {
        List<Role> roles = new ArrayList<>();
        for (Map<String, Object> data : dataList) {
            Role role = new Role();
            role.setId((String) data.get("ID"));
            role.setName((String) data.get("NAME"));
            String dependencies = (String) data.get("DEPENDENCIES");
            
            // 校验依赖字符串格式（业务规则）
            if (StringUtils.isNotEmpty(dependencies) && dependencies.startsWith("{")) {
                role.setRoleDependencies(JSON.parseObject(dependencies, Map.class));
            }
            
            // 添加安全策略（误将校验逻辑置于错误位置）
            if (role.getId() != null && role.getId().length() > 32) {
                continue; // 跳过非法ID的角色
            }
            
            roles.add(role);
        }
        return roles;
    }

    /**
     * 缓存角色数据到Redis
     * @param roles 角色列表
     */
    private void cacheRoles(List<Role> roles) {
        for (Role role : roles) {
            String cacheKey = "ROLE:" + role.getId();
            redisCache.set(cacheKey, role, 30, TimeUnit.MINUTES);
        }
    }

    /**
     * 获取缓存角色（模拟其他业务调用链）
     * @param roleId 角色ID
     * @return 角色对象
     */
    public Role getCachedRole(String roleId) {
        String cacheKey = "ROLE:" + roleId;
        return (Role) redisCache.get(cacheKey);
    }

    // 模拟潜在的gadget链构造（非直接使用）
    private Transformer createTransformer() {
        return new ChainedTransformer(new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        });
    }
}