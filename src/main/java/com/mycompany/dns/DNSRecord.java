package com.mycompany.dns;

public class DNSRecord {
    String name;
    String type;
    int ttl;
    String className;
    String value;

    public DNSRecord(String name, String type, int ttl, String className, String value) {
        this.name = name;
        this.type = type;
        this.ttl = ttl;
        this.className = className;
        this.value = value;
    }
}
