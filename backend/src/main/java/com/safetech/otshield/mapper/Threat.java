// File: backend/src/main/java/com/example/loginapp/model/Threat.java
package com.safetech.otshield.mapper;

import java.util.List;

// Simple POJO for Threat Intelligence entries
public class Threat {
    private String id;
    private String title;
    private String description;
    private String source;
    private String date;
    private List<String> tags;
    private String logoUrl;
    private String link;

    public Threat(String id, String title, String description,
                  String source, String date, List<String> tags,
                  String logoUrl, String link) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.source = source;
        this.date = date;
        this.tags = tags;
        this.logoUrl = logoUrl;
        this.link = link;
    }

    // Getters for JSON serialization
    public String getId()           { return id; }
    public String getTitle()        { return title; }
    public String getDescription()  { return description; }
    public String getSource()       { return source; }
    public String getDate()         { return date; }
    public List<String> getTags()   { return tags; }
    public String getLogoUrl()      { return logoUrl; }
    public String getLink()         { return link; }
}