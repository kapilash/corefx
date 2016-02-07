// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once
#include "pal_types.h"
#include "pal_utilities.h"
#include "pal_ntlmapi.h"

//#if !HAVE_GSSFW_HEADERS


#include <assert.h>


enum NetSecurityNative_NtlmMessageType : uint32_t
{
    NetSecurityNative_NtlmNegotiate = 0x00000001,
    NetSecurityNative_NtlmChallenge = 0x00000002,
    NetSecurityNative_NtlmAuthenticate = 0x00000003
};

/*
  A Generic structure useful for handling the following intermediate objects
     DomainNameFields of NegotiateMessage
     WorkStationFields of NegotiateMessage
     TargetNameFields of ChallengeMessage
*/
struct NetSecurityNative_NameField {
    uint16_t length;
    uint16_t maxLength;
    uint32_t offset;
};

static const uint8_t NtlmSignature[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
static const size_t NtlmSignatureLength = 8;
static const uint64_t NetSecurityNative_NtlmVersion = 0;

template <size_t Count>
inline int32_t NetSecurityNative_NtlmSkipIgnorable(uint8_t* buffer, size_t length, size_t &position)
{
    assert(buffer != nullptr);

    position = position + Count;
    return !(position <= length);
}

inline int32_t NetSecurityNative_NtlmReadNBytes(uint8_t* buffer, size_t length, size_t &position, size_t count, uint8_t* destination)
{
    assert(buffer != nullptr);
    assert(destination != nullptr || count > 0);

    position = position + count;
    if (position <= length && count <= length && (position + count) <= length )
    {
	memcpy(destination, buffer + position, count);
	return 0;
    }

    return 1;
}

#ifdef IS_BIGENDIAN_ARCH //big endian
template <typename T>
inline size_t NetSecurityNative_NtlmFillNum(uint8_t* buffer, size_t length, size_t position, T value)
{
    assert(buffer != nullptr);
    assert(sizeof(T) <= (length - position));

    uint8_t temp[sizeof(T)];
    memcpy(temp, value, sizeof(T));
    for(int i=1; i<=sizeof(T); i++)
    {
	buffer[i-1] = temp[sizeof(T) - i]; 
    }

    return sizeof(T);
}

#else // is little-endian?

template <typename T>
inline size_t NetSecurityNative_NtlmFillNum(uint8_t* buffer, size_t length, size_t position, T value)
{
    assert(buffer != nullptr);
    assert(sizeof(T) <= (length - position));

    memcpy(buffer + position, &value, sizeof(T));

    return sizeof(T);
}

#endif // little-endian

template <typename T>
inline int32_t NetSecurityNative_NtlmReadNum(uint8_t* buffer, size_t length, size_t& position, T &value)
{
    assert(buffer != nullptr);
    
    if (position > length || sizeof(T) > (length - position))
    {
	return 1;
    }

    value = 0;
    for(size_t i=0 ; i < sizeof(T); i++, (position)++)
    {
	value |= static_cast<T>(buffer[position]) << (i*8);
    }

    return 0;
}

inline size_t NetSecurityNative_NtlmFillSignature(uint8_t* buffer, size_t length)
{
    assert(buffer != nullptr);
    assert(length >= 8);

    memcpy(buffer, NtlmSignature, NtlmSignatureLength);
    return NtlmSignatureLength;
}

inline int32_t NetSecurityNative_NtlmReadSignature(uint8_t* buffer, size_t length, size_t& position)
{
    assert(buffer != nullptr);
    assert(position <= length);
    assert(length - position >= NtlmSignatureLength);

    int32_t result = memcmp(buffer, NtlmSignature, NtlmSignatureLength);
    if (0 == result)
    {
	position += NtlmSignatureLength;
    }

    return result;
}


inline size_t NetSecurityNative_NtlmFillVersion(uint8_t* buffer, size_t length, size_t position)
{
    return NetSecurityNative_NtlmFillNum(buffer, length, position, NetSecurityNative_NtlmVersion);
}

inline int32_t NetSecurityNative_NtlmReadVersion(uint8_t* buffer, size_t length, size_t& position)
{
    return NetSecurityNative_NtlmSkipIgnorable<sizeof(NetSecurityNative_NtlmVersion)>(buffer, length, position);
}

inline size_t NetSecurityNative_NtlmFillNameField(uint8_t* buffer, size_t length, size_t position, struct NetSecurityNative_NameField& nameField)
{
    assert(buffer != nullptr);
    assert(8 <= (length - position));

    NetSecurityNative_NtlmFillNum(buffer, length, position, nameField.length);
    NetSecurityNative_NtlmFillNum(buffer, length, position + 2, nameField.maxLength);
    NetSecurityNative_NtlmFillNum(buffer, length, position + 4, nameField.offset);
    return 8;
}

inline int32_t NetSecurityNative_NtlmReadNameField(uint8_t* buffer, size_t length, size_t& position, struct NetSecurityNative_NameField& nameField)
{
    assert(buffer != nullptr);
    assert(position < length);

    int32_t res =  NetSecurityNative_NtlmReadNum<uint16_t>(buffer, length, position, nameField.length);
    res += NetSecurityNative_NtlmReadNum<uint16_t>(buffer, length, position, nameField.maxLength);
    res += NetSecurityNative_NtlmReadNum<uint32_t>(buffer, length, position, nameField.offset);

    return res;
}

extern "C" size_t NetSecurityNative_NtlmFillNegotiationMsg(uint32_t flags,
							   const char* domain,
							   uint16_t domainlen,
							   const char* host,
							   uint16_t hostlen,
							   struct PAL_NtlmBuffer* buffer);

extern "C" int32_t NetSecurityNative_NtlmReadChallengeMsg(uint8_t* buffer,
							  size_t length,
							  struct PAL_NtlmChallengeMsg* challengeMsg);
// #endif
