# ESP32-P4 wolf-sftp example

이 예제는 ESP32-P4보드에 Hellow World예제에 wolfssl/wolfssh를 포팅한 예제입니다.
PC에 openSSH 서비스를 실행 하고 테스트 하였고 잘 동작 합니다. 방화벽 설정에서 포트제외 설정 필요함.
ethernet을 사용함.
build과정이 너무너무 어렵고, 로컬 components로도 시도해보고, managed_components로도 해보고,
각종 옵션들을 user_settings.h에서 수정해보고 결국 빌드 까지는 성공했습니다.
그러나 인증단계에서 실패 합니다.
openSHH볻 사이즈가 작다고 해서, 실험을 했는데, 다루기 너무 까다롭습니다.
거의 1주일간 시도 하였으나 인증에 실패 했습니다.
사이즈는 openSHH보다 10k정도 작은거 같기는 한데, 너무 어려워서 포기합니다.

## build후 size

We will get back to you as soon as possible.
```
                            Memory Type Usage Summary
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Memory Type/Section ┃ Used [bytes] ┃ Used [%] ┃ Remain [bytes] ┃ Total [bytes] ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ Flash               │       376034 │          │                │               │
│    .text            │       296390 │          │                │               │
│    .rodata          │        79152 │          │                │               │
│    .appdesc         │          256 │          │                │               │
│    .init_array      │          236 │          │                │               │
│ DIRAM               │        82401 │    14.29 │         494063 │        576464 │
│    .text            │        65188 │    11.31 │                │               │
│    .bss             │         8636 │      1.5 │                │               │
│    .data            │         8577 │     1.49 │                │               │
│ HP core RAM         │          134 │     1.64 │           8058 │          8192 │
│    .text            │           74 │      0.9 │                │               │
│    .data            │           60 │     0.73 │                │               │
│ LP RAM              │           24 │     0.07 │          32744 │         32768 │
│    .rtc_reserved    │           24 │     0.07 │                │               │
└─────────────────────┴──────────────┴──────────┴────────────────┴───────────────┘
Total image size: 449697 bytes (.bin may be padded larger)
```
