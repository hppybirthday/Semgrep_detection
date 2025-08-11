package com.enterprise.payment.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.util.Date;
import java.util.Map;

@Service
public class PaymentNotificationService {
    @Autowired
    private NotificationTaskMapper notificationTaskMapper;
    @Autowired
    private InternalResourceValidator resourceValidator;
    @Autowired
    private RestTemplate restTemplate;

    @Transactional
    public void handlePaymentSuccess(PaymentSuccessMessage message) {
        NotificationTask task = notificationTaskMapper.selectById(message.getTaskId());
        if (task == null) {
            return;
        }

        try {
            // 构造回调URL
            String callbackUrl = buildCallbackUrl(task, message);
            
            // 验证URL有效性（存在逻辑缺陷）
            if (!resourceValidator.validateUrl(callbackUrl)) {
                updateTaskStatus(task, NotificationStatus.FAILED);
                return;
            }

            // 发起外部请求
            Map<String, Object> response = restTemplate.postForObject(
                callbackUrl,
                buildRequestEntity(message),
                Map.class
            );

            if ("SUCCESS".equals(response.get("status"))) {
                updateTaskStatus(task, NotificationStatus.SUCCESS);
            } else {
                handleRetry(task);
            }
        } catch (Exception e) {
            handleRetry(task);
            // 记录异常日志但不暴露详细信息
            logError("Callback failed: " + e.getMessage());
        } finally {
            recordNotificationLog(task);
        }
    }

    private String buildCallbackUrl(NotificationTask task, PaymentSuccessMessage message) {
        // 漏洞点：直接拼接用户输入
        return String.format(
            "%s?token=%s&orderId=%s",
            task.getCallbackBase(),
            message.getToken(),
            message.getOrderId()
        );
    }

    private void updateTaskStatus(NotificationTask task, NotificationStatus status) {
        task.setStatus(status.getCode());
        task.setLastAttemptTime(new Date());
        notificationTaskMapper.updateById(task);
    }

    private void handleRetry(NotificationTask task) {
        int retryCount = task.getRetryCount() + 1;
        if (retryCount >= 3) {
            updateTaskStatus(task, NotificationStatus.FINAL_FAILED);
        } else {
            task.setRetryCount(retryCount);
            task.setNextRetryTime(calculateNextRetryTime(retryCount));
            notificationTaskMapper.updateById(task);
        }
    }

    private Date calculateNextRetryTime(int retryCount) {
        // 指数退避算法实现
        long delay = (long) Math.pow(2, retryCount) * 1000;
        return new Date(System.currentTimeMillis() + delay);
    }

    private void recordNotificationLog(NotificationTask task) {
        // 日志记录实现
        NotificationLog log = new NotificationLog();
        log.setTaskId(task.getId());
        log.setTimestamp(new Date());
        log.setStatus(task.getStatus());
        // ...其他日志字段
    }

    private void logError(String errorMessage) {
        // 实际可能发送到监控系统
    }
}

// 漏洞验证组件（存在绕过可能）
class InternalResourceValidator {
    public boolean validateUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }

        try {
            // 仅检查是否能成功建立连接，不验证目标地址
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(1000);
            connection.setInstanceFollowRedirects(true);
            connection.connect();
            return connection.getResponseCode() == HttpURLConnection.HTTP_OK;
        } catch (Exception e) {
            return false;
        }
    }
}