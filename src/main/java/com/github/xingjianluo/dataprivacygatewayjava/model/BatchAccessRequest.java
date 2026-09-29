package com.github.xingjianluo.dataprivacygatewayjava.model;

import java.util.List;

/** 批量访问请求：调用方身份 + 持证等级 + 是否取原文 + 多条条目。 */
public final class BatchAccessRequest {
    private final String caller;
    private final Level clearance;
    private final boolean rawRequested;
    private final List<BatchItem> items;

    public BatchAccessRequest(String caller, Level clearance, boolean rawRequested, List<BatchItem> items) {
        this.caller = caller;
        this.clearance = clearance;
        this.rawRequested = rawRequested;
        this.items = items == null ? List.of() : List.copyOf(items);
    }

    public String caller() { return caller; }
    public Level clearance() { return clearance; }
    public boolean rawRequested() { return rawRequested; }
    public List<BatchItem> items() { return items; }

    public String getCaller() { return caller; }
    public Level getClearance() { return clearance; }
    public boolean isRawRequested() { return rawRequested; }
    public List<BatchItem> getItems() { return items; }
}
