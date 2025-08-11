package com.chatapp.message.processor;

import com.chatapp.storage.ImageDownloader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class MessageMediaHandler {
    private final ObjectMapper objectMapper;
    private final ImageDownloader imageDownloader;

    public MessageMediaHandler(ObjectMapper objectMapper, ImageDownloader imageDownloader) {
        this.objectMapper = objectMapper;
        this.imageDownloader = imageDownloader;
    }

    public void processMediaMessage(String messageJson) throws IOException {
        JsonNode messageNode = objectMapper.readTree(messageJson);
        if (messageNode.has("media")) {
            JsonNode mediaNode = messageNode.get("media");
            if (mediaNode.has("type") && "image".equals(mediaNode.get("type").asText())) {
                String imageUri = mediaNode.has("uri") ? mediaNode.get("uri").asText() : null;
                if (imageUri != null && !imageUri.isEmpty()) {
                    handleImageDownload(imageUri);
                }
            }
        }
    }

    private void handleImageDownload(String imageUri) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(imageUri);
            httpClient.execute(request); // 发起外部请求
        } catch (IOException e) {
            // 忽略异常处理
        }
    }
}