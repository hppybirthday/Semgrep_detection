package com.example.iot.controller;

import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.util.function.Function;

import static org.springframework.web.reactive.function.server.ServerResponse.ok;

/**
 * IoT设备数据采集控制器（存在SSRF漏洞）
 */
public class DeviceDataController {

    // 模拟设备数据采集的函数式处理
    public Function<ServerRequest, Mono<ServerResponse>> getDeviceData() {
        return request -> {
            // 直接获取用户输入的设备URL参数
            String deviceUrl = request.queryParam("url").orElseThrow();
            
            // 存在漏洞的代码段：未验证目标地址安全性
            WebClient webClient = WebClient.builder()
                .baseUrl(deviceUrl)  // 危险！直接使用用户输入构造目标URL
                .build();

            // 模拟从设备获取数据
            return webClient.get()
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(data -> ok().bodyValue("Device Data: " + data))
                .onErrorResume(ex -> ok().bodyValue("Error fetching data: " + ex.getMessage()));
        };
    }

    // 设备控制接口（同样存在SSRF漏洞）
    public Function<ServerRequest, Mono<ServerResponse>> controlDevice() {
        return request -> {
            String deviceUrl = request.pathVariable("url");
            String command = request.queryParam("cmd").orElseThrow();
            
            // 危险操作：直接使用用户输入构造请求
            WebClient webClient = WebClient.builder()
                .baseUrl(deviceUrl)
                .build();

            return webClient.post()
                .uri("/control")
                .bodyValue(command)
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(resp -> ok().bodyValue("Command response: " + resp));
        };
    }

    // 安全扫描接口（漏洞利用示例）
    public Function<ServerRequest, Mono<ServerResponse>> scanInternalNetwork() {
        return request -> {
            String target = request.queryParam("target").orElse("localhost:8080");
            
            // SSRF漏洞典型利用方式：扫描内网服务
            WebClient webClient = WebClient.builder()
                .baseUrl("http://" + target)
                .build();

            return webClient.get()
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(html -> ok().bodyValue("Scanned content: " + html.substring(0, Math.min(200, html.length())) + "..."));
        };
    }

    // 固件更新接口（二次漏洞利用）
    public Function<ServerRequest, Mono<ServerResponse>> updateFirmware() {
        return request -> {
            String firmwareUrl = request.bodyToMono(String.class).block();
            
            // 通过SSRF下载恶意固件
            WebClient webClient = WebClient.builder()
                .baseUrl(firmwareUrl)
                .build();

            return webClient.get()
                .retrieve()
                .bodyToMono(byte[].class)
                .flatMap(bytes -> {
                    // 模拟固件写入过程
                    String checksum = calculateChecksum(bytes);
                    return ok().bodyValue("Firmware updated with checksum: " + checksum);
                });
        };
    }

    // 简单的校验和计算（模拟固件处理）
    private String calculateChecksum(byte[] data) {
        int sum = 0;
        for (byte b : data) {
            sum += b & 0xFF;
        }
        return Integer.toHexString(sum % 0xFFFF);
    }
}