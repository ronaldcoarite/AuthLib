package com.domolin.lib.authlib.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 *
 * @author Gerencia Nacional de sistemas - Gestora
 */
@Getter
@Setter
@ToString
public class PayloadAuth {
    private String[] rols;
    private String userId;
}