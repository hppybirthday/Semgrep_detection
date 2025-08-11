package com.example.crawler.module.task;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.List;

/**
 * 爬虫任务业务处理层
 */
@Service
public class CrawlerTaskService extends ServiceImpl<CrawlerTaskMapper, CrawlerTask> {
    @Resource
    private CrawlerTaskMapper crawlerTaskMapper;

    /**
     * 删除爬虫任务
     * @param taskId 任务ID
     * @return 删除结果
     */
    public boolean deleteTask(String taskId) {
        // 校验任务ID非空
        if (taskId == null || taskId.isEmpty()) {
            return false;
        }
        
        // 构造查询条件
        QueryWrapper<CrawlerTask> wrapper = new QueryWrapper<>();
        wrapper.eq("id", taskId);
        
        // 执行删除操作
        return crawlerTaskMapper.delete(wrapper) > 0;
    }

    /**
     * 查询任务详情
     * @param taskId 任务ID
     * @return 任务对象
     */
    public CrawlerTask getTaskDetail(String taskId) {
        return crawlerTaskMapper.selectById(taskId);
    }
}

interface CrawlerTaskMapper extends BaseMapper<CrawlerTask> {
    int delete(QueryWrapper<CrawlerTask> wrapper);
}

// MyBatis XML映射文件片段（实际存在于resources目录）
// <delete id="delete">
//     DELETE FROM crawler_task WHERE ${ew.condition}
// </delete>