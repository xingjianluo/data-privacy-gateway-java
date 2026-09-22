package com.github.xingjianluo.dataprivacygatewayjava.model;

/** 访问请求：调用方身份、持证等级、目标记录、是否显式请求原始值。 */
public final class AccessRequest {
    private final String caller;
    private final Level clearance;
    private final String recordId;
    private final boolean rawRequested;

    public AccessRequest(String caller, Level clearance, String recordId, boolean rawRequested) {
        this.caller = caller;
        this.clearance = clearance;
        this.recordId = recordId;
        this.rawRequested = rawRequested;
    }

    public String caller() { return caller; }
    public Level clearance() { return clearance; }
    public String recordId() { return recordId; }
    public boolean rawRequested() { return rawRequested; }
}
