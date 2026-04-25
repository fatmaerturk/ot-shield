package com.safetech.otshield.controller;

import com.safetech.otshield.model.BlockingRule;
import com.safetech.otshield.service.BlockingRuleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/honeypot/rules")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class BlockingRuleController {

    private final BlockingRuleService service;

    public BlockingRuleController(BlockingRuleService service) {
        this.service = service;
    }

    @GetMapping
    public List<BlockingRule> list() { return service.list(); }

    @PostMapping
    public BlockingRule create(@RequestBody BlockingRule rule) { return service.create(rule); }

    @PutMapping("/{id}")
    public BlockingRule update(@PathVariable Long id, @RequestBody BlockingRule rule) { return service.update(id, rule); }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) { service.delete(id); return ResponseEntity.noContent().build(); }
}


