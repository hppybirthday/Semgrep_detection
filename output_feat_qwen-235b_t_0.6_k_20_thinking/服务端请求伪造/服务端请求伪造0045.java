package com.example.mathsim.gateway;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

@Component
public class SSRFGatewayFilter extends AbstractGatewayFilterFactory<SSRFGatewayFilter.Config> {
    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String requestUri = exchange.getRequest().getURI().getPath();
            // 漏洞点：直接将路径参数作为URL使用
            String targetUrl = "http://data-repo.example.com/models/" + requestUri.split("/fetch/")[1];
            
            try {
                // 模拟元编程动态执行
                String script = String.format("import java.net.*; URL url = new URL(\\"%s\\"); " +
                    "InputStream is = url.openStream(); ByteArrayOutputStream os = new ByteArrayOutputStream(); " +
                    "byte[] buffer = new byte[1024]; int len; while((len = is.read(buffer))!=-1) { os.write(buffer,0,len); } " +
                    "new FileOutputStream(\\"/tmp/model_data.bin\\").write(os.toByteArray());", targetUrl);
                
                // 动态编译执行（模拟元编程特性）
                executeDynamicScript(script);
                
                // 返回元数据
                Path filePath = Files.createTempFile("model_", ".bin");
                HttpHeaders headers = new HttpHeaders();
                headers.setContentDispositionFormData("attachment", filePath.getFileName().toString());
                
                return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                    .bufferFactory().wrap(headers.toString().getBytes())));
                    
            } catch (Exception e) {
                return Mono.error(new RuntimeException("File fetch failed"));
            }
        };
    }

    private void executeDynamicScript(String script) throws Exception {
        // 模拟动态执行环境（实际场景可能使用Groovy/JavaScript引擎）
        // 这里简化为直接执行构造的代码字符串
        System.out.println("Executing dynamic script: " + script);
        // 实际执行逻辑会触发SSRF漏洞
    }

    public static class Config {
        // 配置属性
    }
}