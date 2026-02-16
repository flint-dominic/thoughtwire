/*
 * Thoughtwire Protocol — C Header
 * Auto-generated from protocol.py
 * DO NOT EDIT — regenerate with: thoughtwire schema --format c
 * Generated: 2026-02-16 20:04:37 UTC
 */

#ifndef THOUGHTWIRE_H
#define THOUGHTWIRE_H

#include <stdint.h>

#define TW_VERSION_1 1
#define TW_VERSION_2 2
#define TW_MAX_PAYLOAD 65535
#define TW_V1_HEADER_SIZE 14
#define TW_V2_HEADER_SIZE 16
#define TW_ED25519_SIG_SIZE 64

/* Frame Types */
#define TW_FRAME_CHAT 0
#define TW_FRAME_VOTE 1
#define TW_FRAME_STATE_DIFF 2
#define TW_FRAME_ATTENTION 3
#define TW_FRAME_SYSTEM 4
#define TW_FRAME_HEARTBEAT 5
#define TW_FRAME_ERROR 6
#define TW_FRAME_ACK 7

/* Intents */
#define TW_INTENT_INFORM 0
#define TW_INTENT_REQUEST 1
#define TW_INTENT_PROPOSE 2
#define TW_INTENT_APPROVE 3
#define TW_INTENT_REJECT 4
#define TW_INTENT_RESPOND 5
#define TW_INTENT_QUERY 6
#define TW_INTENT_DELEGATE 7

/* Known Agents */
#define TW_AGENT_GPT 0x998FF305U
#define TW_AGENT_NIX 0xC01FF43EU
#define TW_AGENT_LLAMA 0xC01FF43EU
#define TW_AGENT_GEMINI 0xC814C38CU

/* V1 Frame Header (14 bytes, packed, network byte order) */
typedef struct __attribute__((packed)) {
    uint8_t  version;
    uint8_t  frame_type;
    uint32_t agent_id;
    uint32_t timestamp;
    uint8_t  confidence;    /* 0-255 → 0.0-1.0 */
    uint8_t  intent;
    int16_t  payload_len;
} tw_frame_v1_t;

/* V2 Frame Header (16 bytes, packed, network byte order) */
typedef struct __attribute__((packed)) {
    uint8_t  version;
    uint8_t  frame_type;
    uint32_t agent_id;
    uint32_t timestamp;
    uint8_t  confidence;
    uint8_t  intent;
    int16_t  payload_len;
    uint16_t sig_len;       /* 0 = unsigned, 64 = Ed25519 */
} tw_frame_v2_t;

/* Decode confidence byte to float */
static inline float tw_confidence(uint8_t raw) {
    return raw / 255.0f;
}

/* Encode confidence float to byte */
static inline uint8_t tw_encode_confidence(float conf) {
    if (conf < 0.0f) conf = 0.0f;
    if (conf > 1.0f) conf = 1.0f;
    return (uint8_t)(conf * 255.0f);
}

#endif /* THOUGHTWIRE_H */
