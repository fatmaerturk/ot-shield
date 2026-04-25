package com.safetech.otshield.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureWebMvc
public class FileControllerTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Test
    public void testPcapHealthCheck() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        
        mockMvc.perform(get("/api/health/pcap"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").exists());
    }

    @Test
    public void testPcapUploadWithEmptyFile() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        
        MockMultipartFile file = new MockMultipartFile(
            "pcap", 
            "test.pcap", 
            "application/octet-stream", 
            new byte[0]
        );
        
        mockMvc.perform(multipart("/api/upload/pcap")
                .file(file))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testPcapUploadWithInvalidFileType() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        
        MockMultipartFile file = new MockMultipartFile(
            "pcap", 
            "test.txt", 
            "text/plain", 
            "test content".getBytes()
        );
        
        mockMvc.perform(multipart("/api/upload/pcap")
                .file(file))
                .andExpect(status().isBadRequest());
    }
} 