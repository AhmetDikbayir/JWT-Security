package com.tpe.dto;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class LoginRequest {

    @NotBlank
    private String userName;

    @NotBlank
    private String password;
}
