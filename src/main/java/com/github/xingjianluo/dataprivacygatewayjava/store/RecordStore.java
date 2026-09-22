package com.github.xingjianluo.dataprivacygatewayjava.store;

import com.github.xingjianluo.dataprivacygatewayjava.model.NormalizedRecord;
import com.github.xingjianluo.dataprivacygatewayjava.util.JsonCodec;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存记录库。写入与读取都做深拷贝，切断与调用方之间的共享引用，
 * 保证内部状态不会被外部并发修改，也避免“失败后残留部分处理状态”。
 */
@Component
public class RecordStore {

    private final ConcurrentHashMap<String, NormalizedRecord> records = new ConcurrentHashMap<>();

    public RecordStore() {
    }

    public void put(NormalizedRecord record) {
        NormalizedRecord safe = new NormalizedRecord(
                record.recordId(),
                record.source(),
                record.ingestedAt(),
                deepCopyMap(record.data()),
                List.copyOf(record.rejectedFields()));
        records.put(safe.recordId(), safe);
    }

    /** 返回记录的防御性拷贝；不存在返回 null。 */
    public NormalizedRecord get(String recordId) {
        NormalizedRecord r = records.get(recordId);
        if (r == null) {
            return null;
        }
        return new NormalizedRecord(r.recordId(), r.source(), r.ingestedAt(),
                deepCopyMap(r.data()), List.copyOf(r.rejectedFields()));
    }

    public boolean exists(String recordId) {
        return records.containsKey(recordId);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> deepCopyMap(Map<String, Object> data) {
        return (Map<String, Object>) JsonCodec.deepCopy(data);
    }
}
