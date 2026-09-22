package com.github.xingjianluo.dataprivacygatewayjava.config;

import com.github.xingjianluo.dataprivacygatewayjava.model.CallerIdentity;
import com.github.xingjianluo.dataprivacygatewayjava.model.DataClassification;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 调用方目录（内存）：演示用身份及其许可集。
 */
public class CallerDirectory {

    private final Map<String, CallerIdentity> callers = new ConcurrentHashMap<>();

    public void register(CallerIdentity caller) {
        callers.put(caller.callerId(), caller);
    }

    public CallerIdentity resolve(String callerId) {
        return callers.get(callerId);
    }

    public int size() {
        return callers.size();
    }

    /** 预置：guest（仅公开）、analyst（到 PII）、auditor（全许可）。 */
    public static CallerDirectory demo() {
        CallerDirectory dir = new CallerDirectory();
        dir.register(new CallerIdentity("guest",
                Set.of(DataClassification.PUBLIC, DataClassification.INTERNAL)));
        dir.register(new CallerIdentity("analyst",
                Set.of(DataClassification.PUBLIC, DataClassification.INTERNAL, DataClassification.PII)));
        dir.register(new CallerIdentity("auditor",
                Set.of(DataClassification.values())));
        return dir;
    }
}
