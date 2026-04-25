package com.safetech.otshield.event;

import com.safetech.otshield.service.ConpotService;
import org.springframework.context.ApplicationEvent;

public class ConpotStatusEvent extends ApplicationEvent {
    
    private final ConpotService conpotService;
    
    public ConpotStatusEvent(ConpotService conpotService) {
        super(conpotService);
        this.conpotService = conpotService;
    }
    
    public ConpotService getConpotService() {
        return conpotService;
    }
} 