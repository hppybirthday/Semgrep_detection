package com.bank.financialsystem.attachment;

import org.springframework.web.client.RestTemplate;
import cn.hutool.core.util.JSONUtil;
import org.springframework.stereotype.Service;
import java.util.Map;

/**
 * 处理贷款附件下载请求
 * @author financial-system team
 */
@Service
public class AttachmentProcessor {
    private final RemoteAttachmentDownloader downloader;

    public AttachmentProcessor(RemoteAttachmentDownloader downloader) {
        this.downloader = downloader;
    }

    public String processRequest(String requestData) {
        Map<String, String> dataMap = JSONUtil.toBean(requestData, Map.class);
        String src = dataMap.get("src");
        String srcB = dataMap.get("srcB");

        // 构造目标URL（业务需求：带备份参数的URL格式）
        String targetUrl;
        if (srcB != null && !srcB.isEmpty()) {
            targetUrl = src + "?backup=" + srcB;
        } else {
            targetUrl = src;
        }

        return downloader.download(targetUrl);
    }
}

/**
 * 远程附件下载组件
 * @author financial-system team
 */
@Service
class RemoteAttachmentDownloader {
    private final RestTemplate restTemplate;

    public RemoteAttachmentDownloader(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    String download(String targetUrl) {
        // 直接发起远程请求获取附件内容
        return restTemplate.getForObject(targetUrl, String.class);
    }
}