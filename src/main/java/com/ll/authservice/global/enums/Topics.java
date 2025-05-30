package com.ll.authservice.global.enums;

import lombok.Getter;

@Getter
public enum Topics {
  SIGNUP("signup"),
  GITHUB_LOGIN("github_login");

  // Getter 메서드
  private final String topicName;

  Topics(String topicName) {
    this.topicName = topicName;
  }
}

