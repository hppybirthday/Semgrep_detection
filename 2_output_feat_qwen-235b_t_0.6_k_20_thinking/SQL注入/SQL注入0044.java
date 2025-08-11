package com.example.crawler.module.task;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.util.List;

/**
 * 爬虫任务服务类
 * 处理任务配置查询业务
 */
@Service
public class CrawlerTaskService extends ServiceImpl<CrawlerTaskMapper, CrawlerTask> {
    @Resource
    private CrawlerTaskMapper crawlerTaskMapper;

    /**
     * 根据条件查询爬虫任务
     * @param mainId 主任务ID
     * @param name 任务名称
     * @return 匹配的任务列表
     */
    public List<CrawlerTask> queryTasks(String mainId, String name) {
        QueryWrapper<CrawlerTask> queryWrapper = new QueryWrapper<>();
        
        // 构造查询条件
        if (StringUtils.hasText(mainId)) {
            // 使用字符串拼接构造自定义条件
            queryWrapper.apply("main_id = '" + mainId + "' AND status = 1");
        }
        
        if (StringUtils.hasText(name)) {
            // 安全的参数化查询（形成对比）
            queryWrapper.like("name", name);
        }

        return crawlerTaskMapper.selectList(queryWrapper);
    }
}

/**
 * 爬虫任务实体类
 */
class CrawlerTask {
    private Long id;
    private String mainId;
    private String name;
    private Integer status;
    // 省略getter/setter
}

/**
 * 爬虫任务数据访问接口
 */
interface CrawlerTaskMapper extends com.baomidou.mybatisplus.core.mapper.BaseMapper<CrawlerTask> {}