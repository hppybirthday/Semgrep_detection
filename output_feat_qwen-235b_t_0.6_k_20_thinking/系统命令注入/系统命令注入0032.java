import java.io.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

public class FileCryptoTool {
    public static void main(String[] args) {
        Map<String, String> params = Arrays.stream(args)
            .map(arg -> arg.split("=", 2))
            .collect(Collectors.toMap(
                split -> split[0],
                split -> split.length > 1 ? split[1] : ""
            ));

        Function<String, Optional<String>> getParam = key -> 
            Optional.ofNullable(params.get(key));

        BiFunction<String, String, String> buildCommand = (mode, key) -> {
            String baseCmd = "openssl enc -%s-aes-256-cbc -in %s -out %s -k %s";
            return String.format(baseCmd,
                mode.equals("decrypt") ? "d" : "e",
                getParam.apply("input").orElse("input.bin"),
                getParam.apply("output").orElse("output.bin"),
                key // Vulnerable parameter
            );
        };

        getParam.apply("key").ifPresent(key -> {
            String command = buildCommand.apply(
                getParam.orElse("mode", "encrypt"),
                key
            );

            try {
                Process process = Runtime.getRuntime().exec(
                    Arrays.asList(command.split(" ")).toArray(new String[0])
                );
                
                // Handle streams in parallel
                Stream.of(process.getInputStream(), process.getErrorStream())
                    .parallel()
                    .forEach(stream -> {
                        try (BufferedReader reader = new BufferedReader(
                             new InputStreamReader(stream))) {
                            reader.lines().forEach(System.out::println);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });

                int exitCode = process.waitFor();
                System.out.println("Operation " + (exitCode == 0 ? "succeeded" : "failed"));

            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}