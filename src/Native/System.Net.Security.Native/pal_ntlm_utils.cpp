#include "pal_types.h"
#include "pal_utilities.h"
#include "pal_ntlmapi.h"
#include "pal_ntlm_utils.h"

#include <assert.h>
#include <string.h>
#include <iostream>

const uint32_t NegotiateMsgHeaderLength = 32;
const uint32_t NTLMSSP_NEGOTIATE_TARGET_INFO = 1 << 23;

extern "C" size_t NetSecurityNative_NtlmFillNegotiationMsg(uint32_t flags, const char* domain, const uint16_t domainLen, const char* host, const uint16_t hostLen,  struct PAL_NtlmBuffer *buffer)
{
    size_t netSize = UnsignedCast(NegotiateMsgHeaderLength) + UnsignedCast(domainLen) + UnsignedCast(hostLen);
    uint8_t* data = new uint8_t[netSize];
    buffer->data = data;
    buffer->length = netSize;
    
    size_t position =  NetSecurityNative_NtlmFillSignature(data, netSize);
    assert(position == 8);
    position += NetSecurityNative_NtlmFillNum<uint32_t>(data, netSize, position, NetSecurityNative_NtlmNegotiate);
    assert( position == 12);
    position += NetSecurityNative_NtlmFillNum<uint32_t>(data, netSize, position, flags);
    assert( position = 16);
    struct NetSecurityNative_NameField domainField {.length = domainLen, .maxLength = domainLen, .offset = 0};
    struct NetSecurityNative_NameField wsField {.length = hostLen, .maxLength = hostLen, .offset = 0};
    if (domainLen > 0)
    {
        domainField.offset = NegotiateMsgHeaderLength;
    }

    if (hostLen > 0)
    {
        wsField.offset = NegotiateMsgHeaderLength + UnsignedCast(domainLen);
    }

    position += NetSecurityNative_NtlmFillNameField(data, netSize, position, domainField);
    assert( position = 24);
    position += NetSecurityNative_NtlmFillNameField(data, netSize, position, wsField);
    assert( position = 32);
    memcpy(data + domainField.offset, domain, domainLen);
    position += domainLen;
    memcpy(data + wsField.offset, host, hostLen);
    position += hostLen;
    return position;
}

extern "C" int32_t NetSecurityNative_NtlmReadChallengeMsg(uint8_t* buffer, size_t length, struct PAL_NtlmChallengeMsg* challengeMsg)
{
    size_t position = 0;
    challengeMsg->targetNameLen = 0;
    challengeMsg->targetName = nullptr;
    challengeMsg->targetInfo = nullptr;
    int32_t retval = NetSecurityNative_NtlmReadSignature(buffer, length, position);

    if (retval)
    {
        return retval;
    }

    uint32_t messageType;
    retval = NetSecurityNative_NtlmReadNum(buffer, length, position, messageType);
    if (retval > 0 || messageType != NetSecurityNative_NtlmChallenge)
    {
        return retval;
    }

    struct NetSecurityNative_NameField targetNameFields{ .length = 0, .maxLength = 0, .offset = 0};
    retval = NetSecurityNative_NtlmReadNameField(buffer, length, position, targetNameFields);
    if (retval > 0)
    {
        return retval;
    }

    uint32_t flags;
    retval = NetSecurityNative_NtlmReadNum(buffer, length, position, flags);
    if (retval > 0)
    {
        return retval;
    }

    uint64_t nonce;
    retval = NetSecurityNative_NtlmReadNum(buffer, length, position, nonce);
    if (retval > 0)
    {
        return retval;
    }
    challengeMsg->challenge = nonce;

    NetSecurityNative_NtlmSkipIgnorable<8>(buffer, length, position);
    struct NetSecurityNative_NameField targetInfoFields{ .length = 0, .maxLength = 0, .offset = 0};
    retval = NetSecurityNative_NtlmReadNameField(buffer, length, position, targetInfoFields);
    if (retval > 0)
    {
        return retval;
    }

    if ((flags & PAL_NTLMSSP_REQUEST_TARGET) && targetNameFields.length > 0 && (length >= targetNameFields.offset + targetNameFields.length))
    {
        // target is present.
        challengeMsg->targetNameLen = UnsignedCast(targetNameFields.length);
        uint8_t* destination = new uint8_t[static_cast<size_t>(targetNameFields.length)];
        memcpy(destination, buffer + (targetNameFields.offset), targetNameFields.length);
        challengeMsg->targetName = destination;
    }

    if (flags & NTLMSSP_NEGOTIATE_TARGET_INFO && targetInfoFields.length > 0)
    {
        // TODO: error handling on length and size and in case of error delete targetInfo if present
        // targetInfo is present
        PAL_NtlmBuffer *targetInfoBuffer = new PAL_NtlmBuffer();
        targetInfoBuffer->length = UnsignedCast(targetInfoFields.length);
        targetInfoBuffer->data = new uint8_t[targetInfoFields.length];
        memcpy(&(targetInfoBuffer->data), buffer + targetInfoFields.offset, targetInfoFields.length);
    }

    return retval;
}
