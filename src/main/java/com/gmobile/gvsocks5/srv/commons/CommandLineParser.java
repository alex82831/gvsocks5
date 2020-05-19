package com.gmobile.gvsocks5.srv.commons;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CommandLineParser {

    private final List<List<String>> options;
    private boolean parsed = false;

    public CommandLineParser() {
        options = new ArrayList<>();
    }

    public void parse(String[] args) {
        if(args == null || args.length <= 0) return;
        for(int i = 0; i < args.length; i++) {
            String someStr = args[i].toLowerCase();
            if(someStr.startsWith("--")) {
                someStr = removePrefix("--", someStr);
            } else if(someStr.startsWith("-")) {
                someStr = removePrefix("-", someStr);
            } else {
                continue;
            }
            if(i < args.length - 1) {
                if(!args[i + 1].startsWith("-")) {
                    // name value
                    List<String> option = new ArrayList<>();
                    option.add(someStr);
                    option.add(args[i + 1]);
                    options.add(option);
                    i++;
                } else {
                    List<String> option = new ArrayList<>();
                    option.add(someStr);
                    option.add("");
                    options.add(option);
                }
            } else {
                List<String> option = new ArrayList<>();
                option.add(someStr);
                option.add("");
                options.add(option);
            }
        }
        parsed = true;
    }

    public List<List<String>> getParseResult() {
        assert parsed;
        return options;
    }

    public Map<String, String> getParseResultAsKeyValuePair() {
        assert parsed;
        Map<String, String> result = new HashMap<>();
        for (int i = 0; i < options.size(); i++) {
            List<String> option = options.get(i);
            String key = option.get(0);
            String value = option.get(1);
            if(value == null) value = "";
            result.put(key, value);
        }
        return result;
    }

    public boolean isParsed() {
        return parsed;
    }

    private String removePrefix(String partern, String option) {
        return option.replace(partern, "");
    }
}
