import java.io.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

record DataRecord(String id, Map<String, Object> metadata) implements Serializable {}

public class DataCleaner {
    public static void main(String[] args) {
        Function<String, Optional<List<DataRecord>>> loader = filepath -> {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filepath))) {
                return Optional.of((List<DataRecord>) ois.readObject());
            } catch (Exception e) {
                System.err.println("Load error: " + e.getMessage());
                return Optional.empty();
            }
        };

        UnaryOperator<List<DataRecord>> cleaner = records -> records.stream()
            .filter(r -> r.metadata() != null)
            .map(r -> new DataRecord(r.id(), cleanMetadata(r.metadata())))
            .toList();

        Consumer<List<DataRecord>> saver = records -> {
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("cleaned.data"))) {
                oos.writeObject(records);
                System.out.println("Data saved successfully");
            } catch (IOException e) {
                System.err.println("Save error: " + e.getMessage());
            }
        };

        loader.apply("raw.data")
             .map(cleaner)
             .ifPresent(saver);
    }

    private static Map<String, Object> cleanMetadata(Map<String, Object> metadata) {
        return metadata.entrySet().stream()
            .filter(e -> e.getKey() != null && e.getValue() != null)
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                e -> e.getValue() instanceof String s ? s.strip() : e.getValue()
            ));
    }
}