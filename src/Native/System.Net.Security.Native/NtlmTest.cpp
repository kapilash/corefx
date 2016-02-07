#include <iostream>
#include "pal_ntlm_utils.h"
#include <err.h>
#include <roken.h>
#include <getarg.h>

#include <krb5-types.h> /* or <inttypes.h> */
#include <heimntlm.h>
#include <string.h>

void UtilsTest()
{
    std::cout << "Testing utilities " << std::endl;
    size_t length = 100;
    uint8_t buffer[100];

    for(size_t j=0; j<length; j++)
    {
        buffer[j] = 'H';
    }
    
    NetSecurityNative_NtlmFillSignature(buffer, length);
    size_t i=0;
    assert(buffer[i++] == 'N');
    assert(buffer[i++] == 'T');
    assert(buffer[i++] == 'L');
    assert(buffer[i++] == 'M');
    assert(buffer[i++] == 'S');
    assert(buffer[i++] == 'S');
    assert(buffer[i++] == 'P');
    assert(buffer[i++] == 0);
    assert(i == 8);
    std::cout << "\tvalidated signature fill" << std::endl;
    NetSecurityNative_NtlmFillNum(buffer, length, i, NetSecurityNative_NtlmNegotiate);
    assert(buffer[i++] == 1);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 0);
    assert(i == 12);
    std::cout << "\tvalidated Number fill and NtlmNegotiate MessageType" << std::endl;
    NetSecurityNative_NtlmFillNum(buffer, length, i, NetSecurityNative_NtlmChallenge);
    assert(buffer[i++] == 2);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 0);
    assert(i == 16);
    std::cout << "\tvalidated number fill and NtlmChallenge MessageType" << std::endl;
    NetSecurityNative_NtlmFillNum(buffer, length, i, NetSecurityNative_NtlmAuthenticate);
    assert(buffer[i++] == 3);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 0);
    assert(i == 20);
    std::cout << "\tvalidated number fill and NtlmAuthenticate MessageType" << std::endl;
    NetSecurityNative_NtlmFillVersion(buffer, length, i);
    for (int k=0; k<8; k++)
    {
        assert(buffer[i++] == 0);
    }
    assert(i==28);
    std::cout << "\tvalidated version fill" << std::endl;

    struct NetSecurityNative_NameField domain { .length = 21, .maxLength = 21, .offset = 15};
    NetSecurityNative_NtlmFillNameField(buffer, length, i, domain);
    assert(buffer[i++] == domain.length);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == domain.maxLength);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 15);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 0);
    assert(buffer[i++] == 0);
    assert(i == 36);
    struct NetSecurityNative_NameField biggerDomain { .length = 381, .maxLength = 471, .offset = 131072 };
    NetSecurityNative_NtlmFillNameField(buffer, length, i, biggerDomain);

    int32_t res;
    uint16_t actualLength;
    res = NetSecurityNative_NtlmReadNum<uint16_t>(buffer, length, i, actualLength);
    assert (actualLength == biggerDomain.length);
    assert(i == 38);
    assert(res == 0);

    uint16_t actualMaxLength;
    res = NetSecurityNative_NtlmReadNum<uint16_t>(buffer, length, i, actualMaxLength);
    assert(actualMaxLength == biggerDomain.maxLength);
    assert(i == 40);
    assert(res == 0);

    uint32_t actualOffset;
    res = NetSecurityNative_NtlmReadNum<uint32_t>(buffer, length, i, actualOffset);
    assert(actualOffset == biggerDomain.offset);

    assert(res == 0);
    std::cout << "\tvalidated a full domain and ReadNum" << std::endl;
    size_t expValue = 0;
    res = NetSecurityNative_NtlmReadSignature(buffer, length, expValue);
    assert(res == 0);
    assert(expValue == 8);
    std::cout << "\tvalidated NTLM signature reading " << std::endl;

    assert(i == 44);
    NetSecurityNative_NtlmFillVersion(buffer, length, i);
    res = NetSecurityNative_NtlmReadVersion(buffer, length, i);
    assert(res == 0);
    assert(i == 52);
    std::cout << "\tvalidated Read Version" << std::endl;

    struct NetSecurityNative_NameField domain3 { .length = 0, .maxLength = 0, .offset = 0 };
    NetSecurityNative_NtlmFillNameField(buffer, length, i, biggerDomain);
    res = NetSecurityNative_NtlmReadNameField(buffer, length, i, domain3);
    assert(res == 0);
    assert(i == 60);
    assert(biggerDomain.length == domain3.length);
    assert(biggerDomain.maxLength == domain3.maxLength);
    assert(biggerDomain.offset == domain3.offset);
    std::cout << "\tvalidated Read NameFields" << std::endl;
}

void Type1MessageTest()
{
    std::cout << "testing type 1 message creation " << std::endl;
    const char* domain = "fareast.corp.microsoft.com";
    const char* hostName = "skapila09";
    uint32_t flags = NTLM_NEG_UNICODE|NTLM_NEG_TARGET|NTLM_NEG_NTLM | NTLM_OEM_SUPPLIED_DOMAIN;
    PAL_NtlmBuffer buffer{.length = 0, .data = nullptr};
    NetSecurityNative_NtlmFillNegotiationMsg(flags, domain, static_cast<uint16_t>(strlen(domain)), nullptr, 0, &buffer);

    ntlm_buf testBuffer {.length = buffer.length, .data = buffer.data};
    struct ntlm_type1 decoded;
    int ret = heim_ntlm_decode_type1(&testBuffer, &decoded);
    assert(ret == 0);
    assert(decoded.hostname == nullptr);
    assert(decoded.domain != nullptr);
    assert(strcmp(decoded.domain, domain) == 0);
    assert(decoded.flags == flags);
    std::cout << "\tcreated a buffer with domain name without hostName and parsed it via heimdal api " << std::endl;

    PAL_NtlmBuffer test2{.length = 0, .data = nullptr};
    uint32_t flags2 = NTLM_OEM_SUPPLIED_WORKSTATION | NTLM_NEG_UNICODE|NTLM_NEG_TARGET|NTLM_NEG_NTLM | NTLM_OEM_SUPPLIED_DOMAIN;
    NetSecurityNative_NtlmFillNegotiationMsg(flags2, domain, static_cast<uint16_t>(strlen(domain)), hostName, static_cast<uint16_t>(strlen(hostName)), &test2);
    testBuffer.length = test2.length;
    testBuffer.data = test2.data;
    struct ntlm_type1 decoded2;
    ret = heim_ntlm_decode_type1(&testBuffer, &decoded2);
    assert(ret == 0);
    assert(decoded2.hostname != nullptr);
    assert(decoded2.domain != nullptr);
    assert(strcmp(decoded2.domain, domain) == 0);
    assert(strcmp(decoded2.hostname, hostName) == 0);
    assert(decoded2.flags == flags2);
    std::cout << "\tcreated a buffer with domain name and hostName and successfully parsed it via heimdal api " << std::endl;

    PAL_NtlmBuffer test3{.length = 0, .data = nullptr};
    uint32_t flags3 = NTLM_NEG_UNICODE|NTLM_NEG_TARGET|NTLM_NEG_NTLM ;
    NetSecurityNative_NtlmFillNegotiationMsg(flags3, nullptr, 0, nullptr, 0, &test3);
    testBuffer.length = test3.length;
    testBuffer.data = test3.data;
    struct ntlm_type1 decoded3;
    ret = heim_ntlm_decode_type1(&testBuffer, &decoded3);
    assert(ret == 0);
    assert(decoded3.hostname == nullptr);
    assert(decoded3.domain == nullptr);
    assert(decoded3.flags == flags3);
    std::cout << "\tcreated a buffer without domain name or hostName and successfully parsed it via heimdal api " << std::endl;
}

void Type2MessageTest()
{
    std::cout << "testing type 2 message read " << std::endl;
    const char* target = "HOST/skapila09.fareast.corp.microsoft.com";
    struct ntlm_type2 test1;
    struct ntlm_buf   buffer1;
    uint32_t flags1 =  NTLM_NEG_NTLM | NTLM_TARGET_DOMAIN | PAL_NTLMSSP_REQUEST_TARGET;
    test1.flags = flags1;

    memset(test1.challenge, 0x7f, 8);
    test1.targetname = strdup(target);
    test1.targetinfo.data = NULL;
    test1.targetinfo.length = 0;
    int heimret = heim_ntlm_encode_type2(&test1, &buffer1);
    assert(heimret == 0);
    uint8_t* data = static_cast<uint8_t*>(buffer1.data);
    size_t length = buffer1.length;
    struct PAL_NtlmChallengeMsg challengeMsg;
    int32_t ret = NetSecurityNative_NtlmReadChallengeMsg(data, length, &challengeMsg);
    assert(ret == 0);
    assert(challengeMsg.targetName != nullptr);
    assert(challengeMsg.targetNameLen == strlen(test1.targetname));
    assert( 0 == memcmp(challengeMsg.targetName, target, challengeMsg.targetNameLen));
    uint64_t given = 0;
    for(int i=0; i<8; i++)
    {
        given =  (given << 8)   + ((test1.challenge)[i] & 0xff);
    }
    assert(given == challengeMsg.challenge);
    std::cout<< "\tcreated type2 without targetInfo using heimdal api and successfully parsed it " << std::endl;
}

int main(int argc, char **argv)
{
    for (int i=0; i < argc; i++)
    {
        std::cout << "arg " << i << ". " << argv[i] << std::endl;
    }

    std::cout << "starting tests " << std::endl;

    UtilsTest();
    Type1MessageTest();
    Type2MessageTest();    
    return 0;
}
