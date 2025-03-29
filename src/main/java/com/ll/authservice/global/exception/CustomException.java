package com.ll.authservice.global.exception;


import com.ll.authservice.global.error.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;


@Getter
@AllArgsConstructor
public class CustomException extends RuntimeException {
    private final ErrorCode errorCode;
}
