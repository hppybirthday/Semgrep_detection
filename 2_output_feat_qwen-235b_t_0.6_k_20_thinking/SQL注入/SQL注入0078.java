package com.example.project.module.feedback;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.annotatoin.Sql;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * 反馈数据处理服务
 */
@Service
public class FeedbackService extends ServiceImpl<FeedbackDAO, FeedbackEntity> {

    @Autowired
    private FeedbackDAO feedbackDAO;

    /**
     * 批量删除反馈记录
     * @param ids 待删除记录ID列表
     * @return 删除结果
     */
    public boolean deleteFeedback(List<String> ids) {
        if (ids == null || ids.isEmpty()) {
            return false;
        }
        // 转换为逗号分隔字符串用于日志记录
        String idLog = String.join(",", ids);
        // 执行删除操作
        return feedbackDAO.deleteByIds(idLog);
    }
}

interface FeedbackDAO {
    @Sql("DELETE FROM feedback_table WHERE id IN (${ids})")
    boolean deleteByIds(String ids);
}

class FeedbackEntity {
    private Long id;
    private String content;
    // 省略其他字段及getter/setter
}