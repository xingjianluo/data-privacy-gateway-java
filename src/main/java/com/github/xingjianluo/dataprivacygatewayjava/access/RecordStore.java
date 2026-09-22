package com.github.xingjianluo.dataprivacygatewayjava.access;

import com.github.xingjianluo.dataprivacygatewayjava.model.NormalizedRecord;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 归一化记录内存存储。
 */
public class RecordStore {

    private final ConcurrentHashMap<String, NormalizedRecord> records = new ConcurrentHashMap<>();

    public void put(NormalizedRecord record) {
        records.put(record.recordId(), record);
    }

    public NormalizedRecord get(String recordId) {
        return records.get(recordId);
    }

    public int size() {
        return records.size();
    }
}
