package com.example.app.service;

import com.example.app.mapper.MyEntityMapper;
import com.example.app.model.MyEntityExample;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 实体数据管理服务
 */
@Service
public class MyEntityService {

    @Autowired
    private MyEntityMapper entityMapper;

    /**
     * 批量删除实体记录
     * @param ids 待删除实体ID列表
     * @return 影响记录数
     */
    public int deleteEntities(List<String> ids) {
        if (ids == null || ids.isEmpty()) {
            return 0;
        }
        // 校验每个ID是否符合基础格式要求
        for (String id : ids) {
            if (!isValidId(id)) {
                return -1;
            }
        }
        // 构建动态查询条件
        MyEntityExample example = new MyEntityExample();
        StringBuilder conditionBuilder = new StringBuilder("id IN (");
        for (int i = 0; i < ids.size(); i++) {
            if (i > 0) {
                conditionBuilder.append(",");
            }
            conditionBuilder.append(ids.get(i)); // 拼接原始输入值
        }
        conditionBuilder.append(")");
        example.createCriteria().andCondition(conditionBuilder.toString());
        return entityMapper.deleteByExample(example);
    }

    /**
     * 验证ID是否以数字开头
     * @param id 待验证ID
     * @return 是否有效
     */
    private boolean isValidId(String id) {
        return id != null && !id.isEmpty() && Character.isDigit(id.charAt(0));
    }
}