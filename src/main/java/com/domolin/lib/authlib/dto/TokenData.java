package com.domolin.lib.authlib.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

/**
 *
 * @author Gerencia Nacional de sistemas - Gestora
 */
@Getter
@Setter
public class TokenData {
    private String payload;
    private List<HashMap<String,String>> signatures;

    public TokenData() {
        signatures = new ArrayList<>(1);
    }
}