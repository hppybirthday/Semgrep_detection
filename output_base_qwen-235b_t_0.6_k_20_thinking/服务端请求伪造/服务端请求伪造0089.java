import java.io.*;
import java.net.*;
import java.util.*;

// 高抽象建模接口
interface DataFetcher {
    String fetchData() throws Exception;
}

class RemoteDataFetcher implements DataFetcher {
    private final String targetUrl;

    public RemoteDataFetcher(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    @Override
    public String fetchData() throws Exception {
        URL url = new URL(targetUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        return response.toString();
    }
}

class DataProcessor {
    private final DataFetcher dataFetcher;

    public DataProcessor(DataFetcher dataFetcher) {
        this.dataFetcher = dataFetcher;
    }

    public void process() {
        try {
            String result = dataFetcher.fetchData();
            System.out.println("Data processed: " + result.substring(0, Math.min(50, result.length())) + "...");
        } catch (Exception e) {
            System.err.println("Processing failed: " + e.getMessage());
        }
    }
}

// 大数据处理模拟入口
class BigDataPipeline {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java BigDataPipeline <data-source-url>");
            return;
        }

        try {
            // 高抽象建模：动态选择数据源
            DataFetcher fetcher = new RemoteDataFetcher(args[0]);
            DataProcessor processor = new DataProcessor(fetcher);
            
            // 模拟大数据处理流水线
            for (int i = 0; i < 3; i++) {
                System.out.println("Processing batch " + (i+1));
                processor.process();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}