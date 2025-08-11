package com.example.feedback.service;

import com.example.feedback.mapper.FeedbackMapper;
import com.example.feedback.model.Feedback;
import com.example.feedback.util.QueryBuilder;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import tk.mybatis.mapper.entity.Example;

import java.util.List;

/**
 * 反馈信息查询服务
 * 提供分页搜索和条件过滤功能
 */
@Service
public class FeedbackSearchService {
    @Autowired
    private FeedbackMapper feedbackMapper;

    /**
     * 按条件搜索反馈信息
     * @param type 反馈类型
     * @param keyword 搜索关键词
     * @param pageNum 页码
     * @param pageSize 页面大小
     * @return 分页结果
     */
    public PageInfo<Feedback> searchFeedback(String type, String keyword, int pageNum, int pageSize) {
        PageHelper.startPage(pageNum, pageSize);
        
        Example example = new Example(Feedback.class);
        Example.Criteria criteria = example.createCriteria();
        
        // 构建基础查询条件
        QueryBuilder.buildBaseCriteria(criteria, type, keyword);
        
        // 添加状态过滤条件
        if(StringUtils.isNotBlank(type)) {
            criteria.andEqualTo("status", 1);
        }
        
        List<Feedback> results = feedbackMapper.selectByExample(example);
        return new PageInfo<>(results);
    }
}

// 查询条件构建器
class QueryBuilder {
    /**
     * 构建基础查询条件
     * @param criteria 查询条件容器
     * @param type 反馈类型
     * @param keyword 搜索关键词
     */
    static void buildBaseCriteria(Example.Criteria criteria, String type, String keyword) {
        // 处理类型条件
        if (StringUtils.isNotBlank(type)) {
            // 使用字符串拼接构造查询条件
            criteria.andCondition("type_id = " + type);
        }
        
        // 处理关键词条件
        if (StringUtils.isNotBlank(keyword)) {
            // 对关键词进行基础清理
            String safeKeyword = keyword.replace("'", "''");
            // 构造模糊查询条件
            criteria.andCondition("content LIKE '%" + safeKeyword + "%' ESCAPE '\' ");
        }
    }
}