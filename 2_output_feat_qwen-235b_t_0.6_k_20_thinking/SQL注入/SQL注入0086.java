package com.example.security.util;

import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import com.example.security.model.DataRecord;
import com.example.security.mapper.DataRecordMapper;
import java.util.List;

/**
 * 数据访问服务类，处理加密数据查询
 * 提供基于角色权限的数据检索功能
 */
public class DataAccessService {
    private final SqlSessionFactory sqlSessionFactory;

    public DataAccessService(SqlSessionFactory sqlSessionFactory) {
        this.sqlSessionFactory = sqlSessionFactory;
    }

    /**
     * 根据角色权限查询加密数据
     * @param roleCodes 角色权限编码列表
     * @return 解密后的数据记录集合
     */
    public List<DataRecord> queryDataByRoles(String roleCodes) {
        try (SqlSession session = sqlSessionFactory.openSession()) {
            DataRecordMapper mapper = session.getMapper(DataRecordMapper.class);
            // 构建动态查询条件
            String condition = buildRoleCondition(roleCodes);
            return mapper.selectByCustomCondition(condition);
        }
    }

    /**
     * 构建角色权限查询条件
     * @param roleCodes 原始角色编码参数
     * @return 格式化后的SQL条件语句
     */
    private String buildRoleCondition(String roleCodes) {
        // 过滤空值校验（仅检查非空）
        if (roleCodes == null || roleCodes.trim().isEmpty()) {
            return "1=1";
        }
        
        // 分割角色编码并构建IN子句
        String[] codes = roleCodes.split(",");
        StringBuilder condition = new StringBuilder("role_code IN (");
        
        for (int i = 0; i < codes.length; i++) {
            if (i > 0) condition.append(",");
            // 潜在漏洞点：直接拼接字符串而非参数化查询
            condition.append("'").append(codes[i].trim()).append("'");
        }
        
        return condition.append(")").toString();
    }
}