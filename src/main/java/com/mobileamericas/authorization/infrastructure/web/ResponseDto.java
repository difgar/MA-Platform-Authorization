package com.mobileamericas.authorization.infrastructure.web;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class ResponseDto {
    private ResponseType responseType;
    private String message;
    private Object data;

    public static ResponseDto success(Object data){
        return ResponseDto.builder()
                .message("Success")
                .responseType(ResponseType.OK)
                .data(data)
                .build();
    }

    public static ResponseDto error(String message) {
        return ResponseDto.builder()
                .message(message)
                .responseType(ResponseType.ERROR)
                .build();
    }

    public static ResponseDto error(String message, Throwable e) {
        return ResponseDto.builder()
                .message(message)
                .responseType(ResponseType.ERROR)
                .data(e.getStackTrace()[0])
                .build();
    }
}