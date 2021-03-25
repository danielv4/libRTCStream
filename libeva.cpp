/*
 * libeva
 * Copyright (c) 2020 Kvnode Developers 
 * 
 * support@kvnode.com 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <malloc.h>
#include <assert.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <intrin.h>
#include <ctype.h>
#include "eva.h"

// rtp
#include <srtp2/srtp.h>
#include "zlib.h"
#include <iterator>
#include <thread>
#include <vector>
#include <iostream>



// headers

struct WuCert {

	WuCert();

	~WuCert();

	EVP_PKEY* key;

	X509* x509;

	char fingerprint[96];
};


struct Wu {

	WuArena* arena;

	double time;

	double dt;

	char host[256];

	uint16_t port;

	WuQueue* pendingEvents;

	int32_t maxClients;

	int32_t numClients;

	WuPool* clientPool;

	WuClient** clients;

	ssl_ctx_st* sslCtx;

	char certFingerprint[96];

	char errBuf[512];

	void* userData;

	WuErrorFn errorCallback;

	WuWriteFn writeUdpData;
};



struct WuClient {

	StunUserIdentifier serverUser;

	StunUserIdentifier serverPassword;

	StunUserIdentifier remoteUser;

	StunUserIdentifier remoteUserPassword;

	EvaAddress address;

	WuClientState state;

	uint16_t localSctpPort;

	uint16_t remoteSctpPort;

	uint32_t sctpVerificationTag;

	uint32_t remoteTsn;

	uint32_t tsn;

	double ttl;

	double nextHeartbeat;

	SSL* ssl;

	BIO* inBio;

	BIO* outBio;

	void* user;
};


struct WuConnectionBuffer {
	
	size_t size = 0;
	
	int fd = -1;
	
	uint8_t requestBuffer[1024];
};


struct EvaHost {
	
	Wu* wu;
	
	int tcpfd;
	
	int udpfd;
	
	int epfd;
	
	int pollTimeout;
	
	WuPool* bufferPool;
	
	int32_t maxEvents;
	
	uint16_t port;
	
	char errBuf[512];
};



// functions

static void HostReclaimBuffer(EvaHost* host, WuConnectionBuffer* buffer) {
	buffer->fd = -1;
	buffer->size = 0;
	WuPoolRelease(host->bufferPool, buffer);
}


static WuConnectionBuffer* HostGetBuffer(EvaHost* host) {
	WuConnectionBuffer* buffer = (WuConnectionBuffer*)WuPoolAcquire(host->bufferPool);
	return buffer;
}


static void HandleErrno(EvaHost* host, const char* description) {
	snprintf(host->errBuf, sizeof(host->errBuf), "%s: %s", description, strerror(errno));
	WuReportError(host->wu, host->errBuf);
}


static void WriteUDPData(const uint8_t* data, size_t length,
	const WuClient* client, void* userData) {
	EvaHost* host = (EvaHost*)userData;

	EvaAddress address = WuClientGetAddress(client);
	struct sockaddr_in netaddr;
	netaddr.sin_family = AF_INET;
	netaddr.sin_port = htons(address.port);
	netaddr.sin_addr.s_addr = htonl(address.host);

	sendto(host->udpfd, (const char*)data, length, 0, (struct sockaddr*)&netaddr, sizeof(netaddr));
}


WuSHA1Digest WuSHA1(const uint8_t* src, size_t len, const void* key, size_t keyLen) {

	WuSHA1Digest digest;
	HMAC(EVP_sha1(), key, keyLen, src, len, digest.bytes, NULL);
	return digest;
}


WuCert::WuCert() : key(EVP_PKEY_new()), x509(X509_new()) {

	RSA* rsa = RSA_new();
	BIGNUM* n = BN_new();
	BN_set_word(n, RSA_F4);

	if (!RAND_status()) {
		uint64_t seed = WuRandomU64();
		RAND_seed(&seed, sizeof(seed));
	}

	RSA_generate_key_ex(rsa, 2048, n, NULL);
	EVP_PKEY_assign_RSA(key, rsa);

	BIGNUM* serial = BN_new();
	X509_NAME* name = X509_NAME_new();
	X509_set_pubkey(x509, key);
	BN_pseudo_rand(serial, 64, 0, 0);

	X509_set_version(x509, 0L);
	X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8, (unsigned char*)"wusocket", -1, -1, 0);
	X509_set_subject_name(x509, name);
	X509_set_issuer_name(x509, name);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);
	X509_sign(x509, key, EVP_sha1());

	unsigned int len = 32;
	uint8_t buf[32] = { 0 };
	X509_digest(x509, EVP_sha256(), buf, &len);

	assert(len == 32);
	for (unsigned int i = 0; i < len; i++) {
		if (i < 31) {
			snprintf(fingerprint + i * 3, 4, "%02X:", buf[i]);
		}
		else {
			snprintf(fingerprint + i * 3, 3, "%02X", buf[i]);
		}
	}

	fingerprint[95] = '\0';

	BN_free(n);
	BN_free(serial);
	X509_NAME_free(name);
}


WuCert::~WuCert() {

	EVP_PKEY_free(key);
	X509_free(x509);
}


template <typename T>
T ByteSwap(T v) {

	if (sizeof(T) == 1) {
		return v;
	}
	else if (sizeof(T) == 2) {
		return _byteswap_ushort(uint16_t(v));
	}
	else if (sizeof(T) == 4) {
		return _byteswap_ulong(uint32_t(v));
	}
	else if (sizeof(T) == 8) {
		return _byteswap_uint64(uint64_t(v));
	}
	else {
		assert(0);
		return 0;
	}
}


template <typename T>
size_t WriteScalar(uint8_t* dest, T v) {

	*((T*)dest) = v;
	return sizeof(T);
}


template <typename T>
int32_t ReadScalar(const uint8_t* src, T* v) {

	*v = *(const T*)src;
	return sizeof(T);
}


template <typename T>
size_t WriteScalarSwapped(uint8_t* dest, T v) {

	*((T*)dest) = ByteSwap(v);
	return sizeof(T);
}


template <typename T>
int32_t ReadScalarSwapped(const uint8_t* src, T* v) {

	*v = ByteSwap(*(const T*)src);
	return sizeof(T);
}


inline int32_t PadSize(int32_t numBytes, int32_t alignBytes) {

	return ((numBytes + alignBytes - 1) & ~(alignBytes - 1)) - numBytes;
}


inline int64_t HpCounter() {

#ifdef _WIN32
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	int64_t i64 = li.QuadPart;
#else
	struct timeval t;
	gettimeofday(&t, 0);
	int64_t i64 = t.tv_sec * int64_t(1000000) + t.tv_usec;
#endif

	return i64;
}


inline int64_t HpFreq() {

#ifdef _WIN32
	LARGE_INTEGER li;
	QueryPerformanceFrequency(&li);
	return li.QuadPart;
#else
	return int64_t(1000000);
#endif
}


inline double MsNow() {

	return double(HpCounter()) * 1000.0 / double(HpFreq());
}


template <typename T>
const T& Min(const T& a, const T& b) {

	if (a < b) return a;

	return b;
}


template <typename T>
const T& Max(const T& a, const T& b) {

	if (a > b) return a;

	return b;
}


void HexDump(const uint8_t* src, size_t len) {

	for (size_t i = 0; i < len; i++) {

		if (i % 8 == 0) printf("%04x ", uint32_t(i));

		printf("%02x ", src[i]);

		if ((i + 1) % 8 == 0) printf("\n");
	}

	printf("\n");
}


const int32_t kStunHeaderLength = 20;
const int32_t kStunAlignment = 4;

inline bool StunUserIdentifierEqual(const StunUserIdentifier* a, const StunUserIdentifier* b) {
	return MemEqual(a->identifier, a->length, b->identifier, b->length);
}


bool ParseStun(const uint8_t* src, int32_t len, StunPacket* packet) {
	
	if (len < kStunHeaderLength || src[0] != 0 || src[1] != 1) {
		return false;
	}

	src += ReadScalarSwapped(src, &packet->type);

	if (packet->type != Stun_BindingRequest) {
		return false;
	}

	src += ReadScalarSwapped(src, &packet->length);

	if (packet->length < 4 || packet->length > len - kStunHeaderLength) {
		// Need at least 1 attribute
		return false;
	}

	src += ReadScalarSwapped(src, &packet->cookie);

	for (int32_t i = 0; i < kStunTransactionIdLength; i++) {
		packet->transactionId[i] = src[i];
	}

	src += kStunTransactionIdLength;

	int32_t maxOffset = int32_t(packet->length) - 1;
	int32_t payloadOffset = 0;
	while (payloadOffset < maxOffset) {
		
		int32_t remain = len - kStunHeaderLength - payloadOffset;
		if (remain >= 4) {
			
			uint16_t payloadType = 0;
			uint16_t payloadLength = 0;

			payloadOffset += ReadScalarSwapped(src + payloadOffset, &payloadType);
			payloadOffset += ReadScalarSwapped(src + payloadOffset, &payloadLength);
			remain -= 4;

			int32_t paddedLength = payloadLength + PadSize(payloadLength, kStunAlignment);

			if (payloadType == StunAttrib_User) {
				
				// fragment = min 4 chars
				// username = fragment:fragment (at least 9 characters)
				if (paddedLength <= remain && payloadLength >= 9) {
					const char* uname = (const char*)src + payloadOffset;
					int32_t colonIndex = FindTokenIndex(uname, payloadLength, ':');
					if (colonIndex >= 4) {
						
						int32_t serverUserLength = colonIndex;
						int32_t remoteUserLength = payloadLength - colonIndex - 1;
						if (serverUserLength > kMaxStunIdentifierLength || remoteUserLength > kMaxStunIdentifierLength) {
							return false;
						} 
						else {
							
							packet->serverUser.length = serverUserLength;
							packet->remoteUser.length = remoteUserLength;
							memcpy(packet->serverUser.identifier, uname, serverUserLength);
							memcpy(packet->remoteUser.identifier, uname + colonIndex + 1, remoteUserLength);
							return true;
						}

					} 
					else {
						return false;
					}
				} 
				else {
				  // Actual length > reported length
				  return false;
				}
			}

			payloadOffset += paddedLength;
		} 
		else {
			return false;
		}
	}

	return true;
}


int32_t SerializeStunPacket(const StunPacket* packet, const uint8_t* password, int32_t passwordLen, uint8_t* dest, int32_t len) {
  
	memset(dest, 0, len);
	int32_t offset = WriteScalar(dest, htons(Stun_SuccessResponse));
	// X-MAPPED-ADDRESS (ip4) + MESSAGE-INTEGRITY SHA1
	int32_t contentLength = 12 + 24;
	int32_t contentLengthIntegrity = contentLength + 8;
	const int32_t contentLengthOffset = offset;
	offset += WriteScalar(dest + offset, htons(contentLength));
	offset += WriteScalar(dest + offset, htonl(kStunCookie));

	for (int32_t i = 0; i < 12; i++) {
		dest[i + offset] = packet->transactionId[i];
	}

	offset += 12;

	// xor mapped address attribute ipv4
	offset += WriteScalar(dest + offset, htons(StunAttrib_XorMappedAddress));
	offset += WriteScalar(dest + offset, htons(8));
	offset += WriteScalar(dest + offset, uint8_t(0));  // reserved
	offset += WriteScalar(dest + offset, packet->xorMappedAddress.family);
	offset += WriteScalar(dest + offset, packet->xorMappedAddress.port);
	offset += WriteScalar(dest + offset, packet->xorMappedAddress.address.ipv4);

	WuSHA1Digest digest = WuSHA1(dest, offset, password, passwordLen);

	offset += WriteScalar(dest + offset, htons(StunAttrib_MessageIntegrity));
	offset += WriteScalar(dest + offset, htons(20));

	for (int32_t i = 0; i < 20; i++) {
		dest[i + offset] = digest.bytes[i];
	}

	offset += 20;

	WriteScalar(dest + contentLengthOffset, htons(contentLengthIntegrity));
	uint32_t crc = StunCRC32(dest, offset) ^ 0x5354554e;

	offset += WriteScalar(dest + offset, htons(StunAttrib_Fingerprint));
	offset += WriteScalar(dest + offset, htons(4));
	offset += WriteScalar(dest + offset, htonl(crc));

	return offset;
}


uint32_t StringToUint(const char* s, size_t len) {
	
	uint32_t v = 0;
	uint32_t mul = 1;

	for (size_t i = len; i > 0; i--) {
		uint32_t c = s[i - 1];
		v += (c - '0') * mul;
		mul *= 10;
	}

	return v;
}


bool CompareCaseInsensitive(const char* first, size_t lenFirst, const char* second, size_t lenSecond) {
	
	if (lenFirst != lenSecond) return false;

	for (size_t i = 0; i < lenFirst; i++) {
		if (tolower(first[i]) != second[i]) {
			return false;
		}
	}

	return true;
}


int32_t FindTokenIndex(const char* s, size_t len, char token) {
	
	for (size_t i = 0; i < len; i++) {
		if (s[i] == token) return i;
	}

	return -1;
}


bool MemEqual(const void* first, size_t firstLen, const void* second, size_t secondLen) {

	if (firstLen != secondLen) return false;

	return memcmp(first, second, firstLen) == 0;
}


static bool ValidField(const IceField* field) { 
	
	return field->length > 0; 
}


static bool BeginsWith(const char* s, size_t len, const char* prefix, size_t plen) {
  
	if (plen > len) return false;

	for (size_t i = 0; i < plen; i++) {
		
		char a = s[i];
		char b = prefix[i];

		if (a != b) return false;
	}

	return true;
}


static bool GetIceValue(const char* field, size_t len, const char* name, IceField* o) {

	if (BeginsWith(field, len, name, strlen(name))) {
		for (size_t i = 0; i < len; i++) {
			char c = field[i];
			if (c == ':') {
				size_t valueBegin = i + 1;
				if (valueBegin < len) {
					size_t valueLength = len - valueBegin;
					o->value = field + valueBegin;
					o->length = int32_t(valueLength);
					return true;
				}
				break;
			}
		}
	}

	return false;
}


static void ParseSdpField(const char* field, size_t len, ICESdpFields* fields) {
	
	GetIceValue(field, len, "ice-ufrag", &fields->ufrag);
	GetIceValue(field, len, "ice-pwd", &fields->password);
	GetIceValue(field, len, "mid", &fields->mid);
}


bool ParseSdp(const char* sdp, size_t len, ICESdpFields* fields) {
  
	memset(fields, 0, sizeof(ICESdpFields));

	SdpParseState state = kParseType;
	size_t begin = 0;
	size_t length = 0;

	for (size_t i = 0; i < len; i++) {
		
		char c = sdp[i];
		switch (state) {
			
			case kParseType: {
				
				if (c == 'a') {
					state = kParseEq;
				} 
				else {
					state = kParseIgnore;
				}
				break;
			}
			case kParseEq: {
				
				if (c == '=') {
					state = kParseField;
					begin = i + 1;
					length = 0;
					break;
				} 
				else {
					return false;
				}
			}
			case kParseField: {
				
				switch (c) {
					case '\n': {
						ParseSdpField(sdp + begin, length, fields);
						length = 0;
						state = kParseType;
						break;
					}
					case '\r': {
						state = kParseIgnore;
						ParseSdpField(sdp + begin, length, fields);
						length = 0;
						break;
					};
					default: { 
						length++; 
					}
				}
			}
			default: {
				if (c == '\n') state = kParseType;
			}
		}
	}

	return ValidField(&fields->ufrag) && ValidField(&fields->password) && ValidField(&fields->mid);
}


const char* GenerateSDP(WuArena* arena, const char* certFingerprint, const char* serverIp, uint16_t serverPort, const char* ufrag, int32_t ufragLen, const char* pass, int32_t passLen, const ICESdpFields* remote, int* outLength) {
  
	const uint32_t port = uint32_t(serverPort);
	char buf[4096];

	int32_t length = snprintf(
		buf, sizeof(buf),
		"{\"answer\":{\"sdp\":\"v=0\\r\\n"
		"o=- %u 1 IN IP4 %u\\r\\n"
		"s=-\\r\\n"
		"t=0 0\\r\\n"
		"m=application %u UDP/DTLS/SCTP webrtc-datachannel\\r\\n"
		"c=IN IP4 %s\\r\\n"
		"a=ice-lite\\r\\n"
		"a=ice-ufrag:%.*s\\r\\n"
		"a=ice-pwd:%.*s\\r\\n"
		"a=fingerprint:sha-256 %s\\r\\n"
		"a=ice-options:trickle\\r\\n"
		"a=setup:passive\\r\\n"
		"a=mid:%.*s\\r\\n"
		"a=sctp-port:%u\\r\\n\","
		"\"type\":\"answer\"},\"candidate\":{\"sdpMLineIndex\":0,"
		"\"sdpMid\":\"%.*s\",\"candidate\":\"candidate:1 1 UDP %u %s %u typ "
		"host\"}}",
		WuRandomU32(), port, port, serverIp, ufragLen, ufrag, passLen, pass,
		certFingerprint, remote->mid.length, remote->mid.value, port,
	remote->mid.length, remote->mid.value, WuRandomU32(), serverIp, port);

	if (length <= 0 || length >= int32_t(sizeof(buf))) {
		return NULL;
	}

	char* sdp = (char*)WuArenaAcquire(arena, length);

	if (!sdp) {
		return NULL;
	}

	memcpy(sdp, buf, length);
	*outLength = length;

	return sdp;
}


int32_t ParseSctpPacket(const uint8_t* buf, size_t len, SctpPacket* packet, SctpChunk* chunks, size_t maxChunks, size_t* nChunk) {
	
	
	if (len < 16) {
		return 0;
	}

	int32_t offset = ReadScalarSwapped(buf, &packet->sourcePort);
	offset += ReadScalarSwapped(buf + offset, &packet->destionationPort);
	offset += ReadScalarSwapped(buf + offset, &packet->verificationTag);
	offset += ReadScalarSwapped(buf + offset, &packet->checkSum);

	int32_t left = len - offset;

	size_t chunkNum = 0;
	while (left >= 4 && chunkNum < maxChunks) {
		
		SctpChunk* chunk = &chunks[chunkNum++];

		offset += ReadScalarSwapped(buf + offset, &chunk->type);
		offset += ReadScalarSwapped(buf + offset, &chunk->flags);
		offset += ReadScalarSwapped(buf + offset, &chunk->length);

		*nChunk += 1;

		if (chunk->type == Sctp_Data) {
			
			auto* p = &chunk->as.data;
			size_t chunkOffset = ReadScalarSwapped(buf + offset, &p->tsn);
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &p->streamId);
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &p->streamSeq);
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &p->protoId);
			p->userDataLength = Max(int32_t(chunk->length) - 16, 0);
			p->userData = buf + offset + chunkOffset;
	
		} 
		else if (chunk->type == Sctp_Sack) {
			
			auto* sack = &chunk->as.sack;
			size_t chunkOffset = ReadScalarSwapped(buf + offset, &sack->cumulativeTsnAck);
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &sack->advRecvWindow);
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &sack->numGapAckBlocks);
			ReadScalarSwapped(buf + offset + chunkOffset, &sack->numDupTsn);
		} 
		else if (chunk->type == Sctp_Heartbeat) {
			
			auto* p = &chunk->as.heartbeat;
			size_t chunkOffset = 2;  // skip type
			uint16_t heartbeatLen;
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &heartbeatLen);
			p->heartbeatInfoLen = int32_t(heartbeatLen) - 4;
			p->heartbeatInfo = buf + offset + chunkOffset;
			
		} 
		else if (chunk->type == Sctp_Init) {
			
			size_t chunkOffset = ReadScalarSwapped(buf + offset, &chunk->as.init.initiateTag);
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &chunk->as.init.windowCredit);
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &chunk->as.init.numOutboundStreams);
			chunkOffset += ReadScalarSwapped(buf + offset + chunkOffset, &chunk->as.init.numInboundStreams);
			ReadScalarSwapped(buf + offset + chunkOffset, &chunk->as.init.initialTsn);
		}

		int32_t valueLength = chunk->length - 4;
		int32_t pad = PadSize(valueLength, 4);
		offset += valueLength + pad;
		left = len - offset;
	}

	return 1;
}


size_t SerializeSctpPacket(const SctpPacket* packet, const SctpChunk* chunks, size_t numChunks, uint8_t* dst, size_t dstLen) {
	
	size_t offset = WriteScalar(dst, htons(packet->sourcePort));
	offset += WriteScalar(dst + offset, htons(packet->destionationPort));
	offset += WriteScalar(dst + offset, htonl(packet->verificationTag));

	size_t crcOffset = offset;
	offset += WriteScalar(dst + offset, uint32_t(0));

	for (size_t i = 0; i < numChunks; i++) {
		
		const SctpChunk* chunk = &chunks[i];

		offset += WriteScalar(dst + offset, chunk->type);
		offset += WriteScalar(dst + offset, chunk->flags);
		offset += WriteScalar(dst + offset, htons(chunk->length));

		switch (chunk->type) {
			
			case Sctp_Data: {
				auto* dc = &chunk->as.data;
				offset += WriteScalar(dst + offset, htonl(dc->tsn));
				offset += WriteScalar(dst + offset, htons(dc->streamId));
				offset += WriteScalar(dst + offset, htons(dc->streamSeq));
				offset += WriteScalar(dst + offset, htonl(dc->protoId));
				memcpy(dst + offset, dc->userData, dc->userDataLength);
				int32_t pad = PadSize(dc->userDataLength, 4);
				offset += dc->userDataLength + pad;
				break;
			}
			case Sctp_InitAck: {
				
				offset += WriteScalar(dst + offset, htonl(chunk->as.init.initiateTag));
				offset += WriteScalar(dst + offset, htonl(chunk->as.init.windowCredit));
				offset += WriteScalar(dst + offset, htons(chunk->as.init.numOutboundStreams));
				offset += WriteScalar(dst + offset, htons(chunk->as.init.numInboundStreams));
				offset += WriteScalar(dst + offset, htonl(chunk->as.init.initialTsn));

				offset += WriteScalar(dst + offset, htons(Sctp_StateCookie));
				offset += WriteScalar(dst + offset, htons(8));
				offset += WriteScalar(dst + offset, htonl(0xB00B1E5));
				offset += WriteScalar(dst + offset, htons(Sctp_ForwardTsn));
				offset += WriteScalar(dst + offset, htons(4));

				break;
			}
			case Sctp_Sack: {
				
				auto* sack = &chunk->as.sack;
				offset += WriteScalar(dst + offset, htonl(sack->cumulativeTsnAck));
				offset += WriteScalar(dst + offset, htonl(sack->advRecvWindow));
				offset += WriteScalar(dst + offset, htons(sack->numGapAckBlocks));
				offset += WriteScalar(dst + offset, htons(sack->numDupTsn));
				break;
			}
			case Sctp_Heartbeat:
			case Sctp_HeartbeatAck: {
				
				auto* hb = &chunk->as.heartbeat;
				offset += WriteScalar(dst + offset, htons(1));
				offset += WriteScalar(dst + offset, htons(hb->heartbeatInfoLen + 4));
				memcpy(dst + offset, hb->heartbeatInfo, hb->heartbeatInfoLen);
				offset += hb->heartbeatInfoLen + PadSize(hb->heartbeatInfoLen, 4);
				break;
			}
			case Sctp_Shutdown: {
				
				auto* shutdown = &chunk->as.shutdown;
				offset += WriteScalar(dst + offset, htonl(shutdown->cumulativeTsnAck));
				break;
			}
			case SctpChunk_ForwardTsn: {
				
				auto* forwardTsn = &chunk->as.forwardTsn;
				offset += WriteScalar(dst + offset, htonl(forwardTsn->newCumulativeTsn));
				break;
			}
			default:
				break;
		}
	}

	uint32_t crc = SctpCRC32(dst, offset);
	WriteScalar(dst + crcOffset, htonl(crc));

	return offset;
}


int32_t SctpDataChunkLength(int32_t userDataLength) {
	
	return 16 + userDataLength;
}


int32_t SctpChunkLength(int32_t contentLength) { 
	
	return 4 + contentLength; 
}


static const char kCharacterTable[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static inline uint64_t rotl(const uint64_t x, int k) {
	
	return (x << k) | (x >> (64 - k));
}


uint64_t WuGetRngSeed() {
	
	uint64_t x = __rdtsc();
	uint64_t z = (x += UINT64_C(0x9E3779B97F4A7C15));
	z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
	return z ^ (z >> 31);
}


void WuRngInit(WuRngState* state, uint64_t seed) {
	
	state->s[0] = seed;
	state->s[1] = seed;
}


uint64_t WuRngNext(WuRngState* state) {
	
	const uint64_t s0 = state->s[0];
	uint64_t s1 = state->s[1];
	const uint64_t result = s0 + s1;

	s1 ^= s0;
	state->s[0] = rotl(s0, 55) ^ s1 ^ (s1 << 14);
	state->s[1] = rotl(s1, 36);

	return result;
}


void WuRandomString(char* out, size_t length) {
	
	WuRngState state;
	WuRngInit(&state, WuGetRngSeed());

	for (size_t i = 0; i < length; i++) {
		out[i] = kCharacterTable[WuRngNext(&state) % (sizeof(kCharacterTable) - 1)];
	}
}


uint64_t WuRandomU64() {
	
	WuRngState state;
	WuRngInit(&state, WuGetRngSeed());
	return WuRngNext(&state);
}


uint32_t WuRandomU32() { 

	return (uint32_t)WuRandomU64(); 
}


static int32_t WuQueueFull(const WuQueue* q) {
	
	if (q->length == q->capacity) {
		return 1;
	}

	return 0;
}


WuQueue* WuQueueCreate(int32_t itemSize, int32_t capacity) {
	
	WuQueue* q = (WuQueue*)calloc(1, sizeof(WuQueue));
	WuQueueInit(q, itemSize, capacity);
	return q;
}


void WuQueueInit(WuQueue* q, int32_t itemSize, int32_t capacity) {
	
	memset(q, 0, sizeof(WuQueue));
	q->itemSize = itemSize;
	q->capacity = capacity;
	q->items = (uint8_t*)calloc(q->capacity, itemSize);
}


void WuQueuePush(WuQueue* q, const void* item) {
	
	if (WuQueueFull(q)) {
		
		int32_t newCap = q->capacity * 1.5;
		uint8_t* newItems = (uint8_t*)calloc(newCap, q->itemSize);

		int32_t nUpper = q->length - q->start;
		int32_t nLower = q->length - nUpper;
		memcpy(newItems, q->items + q->start * q->itemSize, q->itemSize * nUpper);
		memcpy(newItems + q->itemSize * nUpper, q->items, q->itemSize * nLower);

		free(q->items);

		q->start = 0;
		q->capacity = newCap;
		q->items = newItems;
	}

	const int32_t insertIdx = ((q->start + q->length) % q->capacity) * q->itemSize;
	memcpy(q->items + insertIdx, item, q->itemSize);
	q->length++;
}


int32_t WuQueuePop(WuQueue* q, void* item) {
	
	if (q->length > 0) {
		
		memcpy(item, q->items + q->start * q->itemSize, q->itemSize);
		q->start = (q->start + 1) % q->capacity;
		q->length--;
		return 1;
	}

	return 0;
}


WuPool* WuPoolCreate(int32_t blockSize, int32_t numBlocks) {
	
	WuPool* pool = (WuPool*)calloc(1, sizeof(WuPool));

	pool->slotSize = blockSize + sizeof(BlockHeader);
	pool->numBytes = pool->slotSize * numBlocks;
	pool->numBlocks = numBlocks;
	pool->memory = (uint8_t*)calloc(pool->numBytes, 1);
	pool->freeIndicesCount = numBlocks;
	pool->freeIndices = (int32_t*)calloc(numBlocks, sizeof(int32_t));

	for (int32_t i = 0; i < numBlocks; i++) {
		pool->freeIndices[i] = numBlocks - i - 1;
	}

	return pool;
}


void WuPoolDestroy(WuPool* pool) {
	
	free(pool->memory);
	free(pool->freeIndices);
	free(pool);
}


void* WuPoolAcquire(WuPool* pool) {
	
	if (pool->freeIndicesCount == 0) return NULL;

	const int32_t index = pool->freeIndices[pool->freeIndicesCount - 1];
	pool->freeIndicesCount--;
	const int32_t offset = index * pool->slotSize;

	uint8_t* block = pool->memory + offset;
	BlockHeader* header = (BlockHeader*)block;
	header->index = index;

	uint8_t* userMem = block + sizeof(BlockHeader);
	return userMem;
}


void WuPoolRelease(WuPool* pool, void* ptr) {
	
	uint8_t* mem = (uint8_t*)ptr - sizeof(BlockHeader);
	BlockHeader* header = (BlockHeader*)mem;
	pool->freeIndices[pool->freeIndicesCount++] = header->index;
}


int32_t eva_host_create(int socket, const char* hostAddr, const char* port, int32_t maxClients, EvaHost** host) {
	
	*host = NULL;

	EvaHost* ctx = (EvaHost*)calloc(1, sizeof(EvaHost));


	if (!ctx) {
		return WU_OUT_OF_MEMORY;
	}

	int32_t status = WuCreate(hostAddr, port, maxClients, &ctx->wu);

	ctx->udpfd = socket;

	const int32_t maxEvents = 128;
	ctx->bufferPool = WuPoolCreate(sizeof(WuConnectionBuffer), maxEvents + 2);

	if (!ctx->bufferPool) {

	}

	WuConnectionBuffer* udpBuf = HostGetBuffer(ctx);
	udpBuf->fd = ctx->udpfd;


	WuSetUserData(ctx->wu, ctx);
	WuSetUDPWriteFunction(ctx->wu, WriteUDPData);

	*host = ctx;

	return EVA_OK;
}


uint32_t StunCRC32(const void* data, int32_t len) {

	uint32_t crc = 0xffffffff;
	const uint8_t* p = (const uint8_t*)data;

	while (len--) {
		uint32_t lkp = crc32Stun[(crc ^ *p++) & 0xFF];
		crc = lkp ^ (crc >> 8);
	}

	return crc ^ 0xffffffff;
}


uint32_t SctpCRC32(const void* data, int32_t len) {
	
	uint32_t crc = 0xFFFFFFFF;

	const uint8_t* p = (const uint8_t*)data;

	for (int32_t i = 0; i < len; i++) {
		CRC32C(crc, p[i]);
	}

	uint32_t result = ~crc;
	uint8_t byte0 = result & 0xff;
	uint8_t byte1 = (result >> 8) & 0xff;
	uint8_t byte2 = (result >> 16) & 0xff;
	uint8_t byte3 = (result >> 24) & 0xff;
	result = ((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);
	
	return result;
}


static void DefaultErrorCallback(const char*, void*) {
	
}


static void WriteNothing(const uint8_t*, size_t, const WuClient*, void*) {
	
}


void WuArenaInit(WuArena* arena, int32_t capacity) {
	
	arena->memory = (uint8_t*)calloc(capacity, 1);
	arena->length = 0;
	arena->capacity = capacity;
}


void* WuArenaAcquire(WuArena* arena, int32_t blockSize) {
	
	assert(blockSize > 0);
	int32_t remain = arena->capacity - arena->length;

	if (remain >= blockSize) {
		uint8_t* m = arena->memory + arena->length;
		arena->length += blockSize;
		return m;
	}

	return NULL;
}


void WuArenaReset(WuArena* arena) { 

	arena->length = 0; 
}


void WuArenaDestroy(WuArena* arena) { 

	free(arena->memory);
}


static int32_t ParseDataChannelControlPacket(const uint8_t* buf, size_t len, DataChannelPacket* packet) {
	
	ReadScalarSwapped(buf, &packet->messageType);
	return 0;
}


void WuReportError(Wu* wu, const char* description) {
	wu->errorCallback(description, wu->userData);
}


void WuClientSetUserData(WuClient* client, void* user) { 
	client->user = user; 
}


void* WuClientGetUserData(const WuClient* client) { 
	return client->user; 
}


static void WuClientFinish(WuClient* client) {
	
	SSL_free(client->ssl);
	client->ssl = NULL;
	client->inBio = NULL;
	client->outBio = NULL;
	client->state = WuClient_Dead;
}


static void WuClientStart(const Wu* wu, WuClient* client) {
	
	client->state = WuClient_DTLSHandshake;
	client->remoteSctpPort = 0;
	client->sctpVerificationTag = 0;
	client->remoteTsn = 0;
	client->tsn = 1;
	client->ttl = kMaxClientTtl;
	client->nextHeartbeat = heartbeatInterval;
	client->user = NULL;

	client->ssl = SSL_new(wu->sslCtx);

	client->inBio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(client->inBio, -1);
	client->outBio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(client->outBio, -1);
	SSL_set_bio(client->ssl, client->inBio, client->outBio);
	SSL_set_options(client->ssl, SSL_OP_SINGLE_ECDH_USE);
	SSL_set_options(client->ssl, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
	SSL_set_tmp_ecdh(client->ssl, EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
	SSL_set_accept_state(client->ssl);
	SSL_set_mtu(client->ssl, kDefaultMTU);
}


static WuClient* WuNewClient(Wu* wu) {

	WuClient* client = (WuClient*)WuPoolAcquire(wu->clientPool);

	if (client) {
		memset(client, 0, sizeof(WuClient));
		WuClientStart(wu, client);
		wu->clients[wu->numClients++] = client;
		return client;
	}

	return NULL;
}


static void WuPushEvent(Wu* wu, EvaEvent evt) {
	
	WuQueuePush(wu->pendingEvents, &evt);
}


static void WuSendSctpShutdown(Wu* wu, WuClient* client) {
	
	SctpPacket response;
	response.sourcePort = client->localSctpPort;
	response.destionationPort = client->remoteSctpPort;
	response.verificationTag = client->sctpVerificationTag;

	SctpChunk rc;
	rc.type = Sctp_Shutdown;
	rc.flags = 0;
	rc.length = SctpChunkLength(sizeof(rc.as.shutdown.cumulativeTsnAck));
	rc.as.shutdown.cumulativeTsnAck = client->remoteTsn;

	WuSendSctp(wu, client, &response, &rc, 1);
}


void WuRemoveClient(Wu* wu, WuClient* client) {
	
	for (int32_t i = 0; i < wu->numClients; i++) {
		if (wu->clients[i] == client) {
			WuSendSctpShutdown(wu, client);
			WuClientFinish(client);
			WuPoolRelease(wu->clientPool, client);
			wu->clients[i] = wu->clients[wu->numClients - 1];
			wu->numClients--;
			return;
		}
	}
}


static WuClient* WuFindClient(Wu* wu, const EvaAddress* address) {
	
	for (int32_t i = 0; i < wu->numClients; i++) {
		WuClient* client = wu->clients[i];
		if (client->address.host == address->host && client->address.port == address->port) {
			return client;
		}
	}

	return NULL;
}


static WuClient* WuFindClientByCreds(Wu* wu, const StunUserIdentifier* svUser, const StunUserIdentifier* clUser) {
	
	for (int32_t i = 0; i < wu->numClients; i++) {
		WuClient* client = wu->clients[i];
		if (StunUserIdentifierEqual(&client->serverUser, svUser) && StunUserIdentifierEqual(&client->remoteUser, clUser)) {
			return client;
		}
	}

	return NULL;
}


static void WuClientSendPendingDTLS(const Wu* wu, WuClient* client) {
	
	uint8_t sendBuffer[4096];

	while (BIO_ctrl_pending(client->outBio) > 0) {
		int bytes = BIO_read(client->outBio, sendBuffer, sizeof(sendBuffer));
		if (bytes > 0) {
			wu->writeUdpData(sendBuffer, bytes, client, wu->userData);
		}
	}
}


static void TLSSend(const Wu* wu, WuClient* client, const void* data, int32_t length) {
	
	if (client->state < WuClient_DTLSHandshake || !SSL_is_init_finished(client->ssl)) {
		return;
	}

	SSL_write(client->ssl, data, length);
	WuClientSendPendingDTLS(wu, client);
}


static void WuSendSctp(const Wu* wu, WuClient* client, const SctpPacket* packet, const SctpChunk* chunks, int32_t numChunks) {

	uint8_t outBuffer[4096];
	memset(outBuffer, 0, sizeof(outBuffer));
	size_t bytesWritten = SerializeSctpPacket(packet, chunks, numChunks, outBuffer, sizeof(outBuffer));
	TLSSend(wu, client, outBuffer, bytesWritten);
}


static void WuHandleSctp(Wu* wu, WuClient* client, const uint8_t* buf, int32_t len) {
	
	const size_t maxChunks = 8;
	SctpChunk chunks[maxChunks];
	SctpPacket sctpPacket;
	size_t nChunk = 0;

	if (!ParseSctpPacket(buf, len, &sctpPacket, chunks, maxChunks, &nChunk)) {
		return;
	}

	for (size_t n = 0; n < nChunk; n++) {
		
		SctpChunk* chunk = &chunks[n];
		
		if (chunk->type == Sctp_Data) {
			
			auto* dataChunk = &chunk->as.data;
			const uint8_t* userDataBegin = dataChunk->userData;
			const int32_t userDataLength = dataChunk->userDataLength;

			client->remoteTsn = Max(chunk->as.data.tsn, client->remoteTsn);
			client->ttl = kMaxClientTtl;

			if (dataChunk->protoId == DCProto_Control) {
				
				DataChannelPacket packet;
				ParseDataChannelControlPacket(userDataBegin, userDataLength, &packet);
				if (packet.messageType == DCMessage_Open) {
					
					client->remoteSctpPort = sctpPacket.sourcePort;
					uint8_t outType = DCMessage_Ack;
					SctpPacket response;
					response.sourcePort = sctpPacket.destionationPort;
					response.destionationPort = sctpPacket.sourcePort;
					response.verificationTag = client->sctpVerificationTag;

					SctpChunk rc;
					rc.type = Sctp_Data;
					rc.flags = kSctpFlagCompleteUnreliable;
					rc.length = SctpDataChunkLength(1);

					auto* dc = &rc.as.data;
					dc->tsn = client->tsn++;
					dc->streamId = chunk->as.data.streamId;
					dc->streamSeq = 0;
					dc->protoId = DCProto_Control;
					dc->userData = &outType;
					dc->userDataLength = 1;

					if (client->state != WuClient_DataChannelOpen) {
						
						client->state = WuClient_DataChannelOpen;
						EvaEvent event;
						event.type = eva_event_client_join;
						event.client = client;
						WuPushEvent(wu, event);
					}

					WuSendSctp(wu, client, &response, &rc, 1);
				}
			} 
			else if (dataChunk->protoId == DCProto_String) {
				
				EvaEvent evt;
				evt.type = eva_event_text_data;
				evt.client = client;
				evt.data = dataChunk->userData;
				evt.length = dataChunk->userDataLength;
				WuPushEvent(wu, evt);
			} 
			else if (dataChunk->protoId == DCProto_Binary) {
				
				EvaEvent evt;
				evt.type = eva_event_binary_data;
				evt.client = client;
				evt.data = dataChunk->userData;
				evt.length = dataChunk->userDataLength;
				WuPushEvent(wu, evt);
			}

			SctpPacket sack;
			sack.sourcePort = sctpPacket.destionationPort;
			sack.destionationPort = sctpPacket.sourcePort;
			sack.verificationTag = client->sctpVerificationTag;

			SctpChunk rc;
			rc.type = Sctp_Sack;
			rc.flags = 0;
			rc.length = SctpChunkLength(12);
			rc.as.sack.cumulativeTsnAck = client->remoteTsn;
			rc.as.sack.advRecvWindow = kSctpDefaultBufferSpace;
			rc.as.sack.numGapAckBlocks = 0;
			rc.as.sack.numDupTsn = 0;

			WuSendSctp(wu, client, &sack, &rc, 1);
		} 
		else if (chunk->type == Sctp_Init) {
			
			SctpPacket response;
			response.sourcePort = sctpPacket.destionationPort;
			response.destionationPort = sctpPacket.sourcePort;
			response.verificationTag = chunk->as.init.initiateTag;
			client->sctpVerificationTag = response.verificationTag;
			client->remoteTsn = chunk->as.init.initialTsn - 1;

			SctpChunk rc;
			rc.type = Sctp_InitAck;
			rc.flags = 0;
			rc.length = kSctpMinInitAckLength;

			rc.as.init.initiateTag = WuRandomU32();
			rc.as.init.windowCredit = kSctpDefaultBufferSpace;
			rc.as.init.numOutboundStreams = chunk->as.init.numInboundStreams;
			rc.as.init.numInboundStreams = chunk->as.init.numOutboundStreams;
			rc.as.init.initialTsn = client->tsn;

			WuSendSctp(wu, client, &response, &rc, 1);
			break;
		} 
		else if (chunk->type == Sctp_CookieEcho) {
			
			if (client->state < WuClient_SCTPEstablished) {
				client->state = WuClient_SCTPEstablished;
			}
			
			SctpPacket response;
			response.sourcePort = sctpPacket.destionationPort;
			response.destionationPort = sctpPacket.sourcePort;
			response.verificationTag = client->sctpVerificationTag;

			SctpChunk rc;
			rc.type = Sctp_CookieAck;
			rc.flags = 0;
			rc.length = SctpChunkLength(0);

			WuSendSctp(wu, client, &response, &rc, 1);
		} 
		else if (chunk->type == Sctp_Heartbeat) {
			
			SctpPacket response;
			response.sourcePort = sctpPacket.destionationPort;
			response.destionationPort = sctpPacket.sourcePort;
			response.verificationTag = client->sctpVerificationTag;

			SctpChunk rc;
			rc.type = Sctp_HeartbeatAck;
			rc.flags = 0;
			rc.length = chunk->length;
			rc.as.heartbeat.heartbeatInfoLen = chunk->as.heartbeat.heartbeatInfoLen;
			rc.as.heartbeat.heartbeatInfo = chunk->as.heartbeat.heartbeatInfo;

			client->ttl = kMaxClientTtl;

			WuSendSctp(wu, client, &response, &rc, 1);
		} 
		else if (chunk->type == Sctp_HeartbeatAck) {
			
			client->ttl = kMaxClientTtl;
		} 
		else if (chunk->type == Sctp_Abort) {
			
			client->state = WuClient_WaitingRemoval;
			return;
		} 
		else if (chunk->type == Sctp_Sack) {
			
			auto* sack = &chunk->as.sack;
			if (sack->numGapAckBlocks > 0) {
				
				SctpPacket fwdResponse;
				fwdResponse.sourcePort = sctpPacket.destionationPort;
				fwdResponse.destionationPort = sctpPacket.sourcePort;
				fwdResponse.verificationTag = client->sctpVerificationTag;

				SctpChunk fwdTsnChunk;
				fwdTsnChunk.type = SctpChunk_ForwardTsn;
				fwdTsnChunk.flags = 0;
				fwdTsnChunk.length = SctpChunkLength(4);
				fwdTsnChunk.as.forwardTsn.newCumulativeTsn = client->tsn;
				WuSendSctp(wu, client, &fwdResponse, &fwdTsnChunk, 1);
			}
		}
	}
}


static void WuReceiveDTLSPacket(Wu* wu, const uint8_t* data, size_t length, const EvaAddress* address) {
	
	WuClient* client = WuFindClient(wu, address);
	if (!client) {
		return;
	}

	BIO_write(client->inBio, data, length);

	if (!SSL_is_init_finished(client->ssl)) {
		
		int r = SSL_do_handshake(client->ssl);

		if (r <= 0) {
			r = SSL_get_error(client->ssl, r);
			if (SSL_ERROR_WANT_READ == r) {
				WuClientSendPendingDTLS(wu, client);
			} 
			else if (SSL_ERROR_NONE != r) {
				char* error = ERR_error_string(r, NULL);
				if (error) {
					WuReportError(wu, error);
				}
			}
		}
	} 
	else {
		
		WuClientSendPendingDTLS(wu, client);

		while (BIO_ctrl_pending(client->inBio) > 0) {
			
			uint8_t receiveBuffer[8092];
			int bytes = SSL_read(client->ssl, receiveBuffer, sizeof(receiveBuffer));

			if (bytes > 0) {
				
				uint8_t* buf = (uint8_t*)WuArenaAcquire(wu->arena, bytes);
				memcpy(buf, receiveBuffer, bytes);
				WuHandleSctp(wu, client, buf, bytes);
			}
		}
	}
}


static void WuHandleStun(Wu* wu, const StunPacket* packet, const EvaAddress* remote) {
	
	WuClient* client = WuFindClientByCreds(wu, &packet->serverUser, &packet->remoteUser);

	if (!client) {
		// TODO: Send unauthorized
		return;
	}

	StunPacket outPacket;
	outPacket.type = Stun_SuccessResponse;
	memcpy(outPacket.transactionId, packet->transactionId, kStunTransactionIdLength);
	outPacket.xorMappedAddress.family = Stun_IPV4;
	outPacket.xorMappedAddress.port = ByteSwap(remote->port ^ kStunXorMagic);
	outPacket.xorMappedAddress.address.ipv4 = ByteSwap(remote->host ^ kStunCookie);

	uint8_t stunResponse[512];
	size_t serializedSize = SerializeStunPacket(&outPacket, client->serverPassword.identifier, client->serverPassword.length, stunResponse, 512);

	client->localSctpPort = remote->port;
	client->address = *remote;

	wu->writeUdpData(stunResponse, serializedSize, client, wu->userData);
}


static void WuPurgeDeadClients(Wu* wu) {
	
	for (int32_t i = 0; i < wu->numClients; i++) {
		
		WuClient* client = wu->clients[i];
		if (client->ttl <= 0.0 || client->state == WuClient_WaitingRemoval) {
			EvaEvent evt;
			evt.type = eva_event_client_leave;
			evt.client = client;
			WuPushEvent(wu, evt);
		}
	}
}


static int32_t WuCryptoInit(Wu* wu) {

	static bool initDone = false;

	if (!initDone) {
		SSL_library_init();
		SSL_load_error_strings();
		ERR_load_BIO_strings();
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		initDone = true;
	}

	wu->sslCtx = SSL_CTX_new(DTLS_server_method());
	if (!wu->sslCtx) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	int sslStatus = SSL_CTX_set_cipher_list(wu->sslCtx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
	if (sslStatus != 1) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	SSL_CTX_set_verify(wu->sslCtx, SSL_VERIFY_NONE, NULL);

	WuCert cert;

	sslStatus = SSL_CTX_use_PrivateKey(wu->sslCtx, cert.key);

	if (sslStatus != 1) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	sslStatus = SSL_CTX_use_certificate(wu->sslCtx, cert.x509);

	if (sslStatus != 1) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	sslStatus = SSL_CTX_check_private_key(wu->sslCtx);

	if (sslStatus != 1) {
		ERR_print_errors_fp(stderr);
		return 0;
	}

	SSL_CTX_set_options(wu->sslCtx, SSL_OP_NO_QUERY_MTU);

	memcpy(wu->certFingerprint, cert.fingerprint, sizeof(cert.fingerprint));

	return 1;
}


int32_t WuCreate(const char* host, const char* port, int maxClients, Wu** wu) {

	*wu = NULL;

	Wu* ctx = (Wu*)calloc(1, sizeof(Wu));

	if (!ctx) {
		return WU_OUT_OF_MEMORY;
	}

	ctx->arena = (WuArena*)calloc(1, sizeof(WuArena));

	if (!ctx->arena) {
		WuDestroy(ctx);
		return WU_OUT_OF_MEMORY;
	}

	WuArenaInit(ctx->arena, 1 << 20);

	ctx->time = MsNow() * 0.001;
	ctx->port = atoi(port);
	ctx->pendingEvents = WuQueueCreate(sizeof(EvaEvent), 1024);
	ctx->errorCallback = DefaultErrorCallback;
	ctx->writeUdpData = WriteNothing;

	strncpy(ctx->host, host, sizeof(ctx->host));

	if (!WuCryptoInit(ctx)) {
		WuDestroy(ctx);
		return WU_ERROR;
	}

	ctx->maxClients = maxClients <= 0 ? 256 : maxClients;
	ctx->clientPool = WuPoolCreate(sizeof(WuClient), ctx->maxClients);
	ctx->clients = (WuClient**)calloc(ctx->maxClients, sizeof(WuClient*));

	*wu = ctx;
	return EVA_OK;
}


static void WuSendHeartbeat(Wu* wu, WuClient* client) {
  
	SctpPacket packet;
	packet.sourcePort = wu->port;
	packet.destionationPort = client->remoteSctpPort;
	packet.verificationTag = client->sctpVerificationTag;

	SctpChunk rc;
	rc.type = Sctp_Heartbeat;
	rc.flags = kSctpFlagCompleteUnreliable;
	rc.length = SctpChunkLength(4 + 8);
	rc.as.heartbeat.heartbeatInfo = (const uint8_t*)&wu->time;
	rc.as.heartbeat.heartbeatInfoLen = sizeof(wu->time);

	WuSendSctp(wu, client, &packet, &rc, 1);
}


static void WuUpdateClients(Wu* wu) {
	
	double t = MsNow() * 0.001;
	wu->dt = t - wu->time;
	wu->time = t;

	for (int32_t i = 0; i < wu->numClients; i++) {
		
		WuClient* client = wu->clients[i];
		client->ttl -= wu->dt;
		client->nextHeartbeat -= wu->dt;

		if (client->nextHeartbeat <= 0.0) {
			client->nextHeartbeat = heartbeatInterval;
			WuSendHeartbeat(wu, client);
		}

		WuClientSendPendingDTLS(wu, client);
	}
}


int32_t eva_update(Wu* wu, EvaEvent* evt) {
	
	if (WuQueuePop(wu->pendingEvents, evt)) {
		return 1;
	}

	WuUpdateClients(wu);
	WuArenaReset(wu->arena);

	WuPurgeDeadClients(wu);

	return 0;
}


static int32_t WuSendData(Wu* wu, WuClient* client, const uint8_t* data, int32_t length, DataChanProtoIdentifier proto) {
	
	if (client->state < WuClient_DataChannelOpen) {
		return -1;
	}
  
	printf("client->state %d\n", client->state);
	printf("WuSendData WuClient_DataChannelOpen\n");

	SctpPacket packet;
	packet.sourcePort = wu->port;
	packet.destionationPort = client->remoteSctpPort;
	packet.verificationTag = client->sctpVerificationTag;

	SctpChunk rc;
	rc.type = Sctp_Data;
	rc.flags = kSctpFlagCompleteUnreliable;
	rc.length = SctpDataChunkLength(length);

	auto* dc = &rc.as.data;
	dc->tsn = client->tsn++;
	dc->streamId = 0;  // TODO: Does it matter?
	dc->streamSeq = 0;
	dc->protoId = proto;
	dc->userData = data;
	dc->userDataLength = length;

	WuSendSctp(wu, client, &packet, &rc, 1);
	return 0;
}


int32_t eva_stream_send_text(Wu* wu, WuClient* client, const char* text, int32_t length) {
	
	return WuSendData(wu, client, (const uint8_t*)text, length, DCProto_String);
}


int32_t eva_stream_send_binary(Wu* wu, WuClient* client, const uint8_t* data, int32_t length) {
	
	return WuSendData(wu, client, data, length, DCProto_Binary);
}


EvaSdp eva_exchange_sdp(Wu* wu, const char* sdp, int32_t length) {
	
	ICESdpFields iceFields;
	if (!ParseSdp(sdp, length, &iceFields)) {
		return {WuSDPStatus_InvalidSDP, NULL, NULL, 0};
	}

	WuClient* client = WuNewClient(wu);

	if (!client) {
		return {WuSDPStatus_MaxClients, NULL, NULL, 0};
	}

	client->serverUser.length = 4;
	WuRandomString((char*)client->serverUser.identifier, client->serverUser.length);
	client->serverPassword.length = 24;
	WuRandomString((char*)client->serverPassword.identifier, client->serverPassword.length);
	memcpy(client->remoteUser.identifier, iceFields.ufrag.value, Min(iceFields.ufrag.length, kMaxStunIdentifierLength));
	client->remoteUser.length = iceFields.ufrag.length;
	memcpy(client->remoteUserPassword.identifier, iceFields.password.value, Min(iceFields.password.length, kMaxStunIdentifierLength));

	int sdpLength = 0;
	const char* responseSdp = GenerateSDP(wu->arena, wu->certFingerprint, wu->host, wu->port, (char*)client->serverUser.identifier, client->serverUser.length, (char*)client->serverPassword.identifier, client->serverPassword.length, &iceFields, &sdpLength);

	if (!responseSdp) {
		return {WuSDPStatus_Error, NULL, NULL, 0};
	}

	return {WuSDPStatus_Success, client, responseSdp, sdpLength};
}


void WuSetUserData(Wu* wu, void* userData) { 

	wu->userData = userData; 
}


void eva_handle_datagram(Wu* wu, const EvaAddress* remote, const uint8_t* data, int32_t length) {
  
	StunPacket stunPacket;
	if (ParseStun(data, length, &stunPacket)) {
	  
		//printf("packet is [stun]\n");
		WuHandleStun(wu, &stunPacket, remote);
	} 
	else {
		WuReceiveDTLSPacket(wu, data, length, remote);
		//printf("packet is [DTLS]\n");
	}
}


void WuSetUDPWriteFunction(Wu* wu, WuWriteFn write) {
	
	wu->writeUdpData = write;
}


EvaAddress WuClientGetAddress(const WuClient* client) { 
	
	return client->address; 
}


void WuSetErrorCallback(Wu* wu, WuErrorFn callback) {
	
	if (callback) {
		
		wu->errorCallback = callback;
	} 
	else {
		wu->errorCallback = DefaultErrorCallback;
	}
}


void WuDestroy(Wu* wu) {
	
	if (!wu) {
		return;
	}

	free(wu);
}


WuClient* WuFindClient(const Wu* wu, EvaAddress address) {
	
	for (int32_t i = 0; i < wu->numClients; i++) {
		
		WuClient* c = wu->clients[i];

		if (c->address.host == address.host && c->address.port == address.port) {
			return c;
		}
	}

	return NULL;
}





// rtp

#define RTP_MAX_PAYLOAD 1400
#define RTP_HEADER_LENGTH 12
#define RTP_VERSION 2
#define RTP_PAYLOAD_ID 100
#define RTP_SSRC 337799
#define VP8_RTP_HEADER_LENGTH 1
#define RTP_LISTEN_PORT 8888
#define DTLS_CERTIFICATE_FILE "localhost.pem"
#define DTLS_KEY_FILE "localhost_key.pem"
#define DTLS_COOKIE "sipsorcery"
#define RECEIVE_BUFFER_LENGTH 65500
#define SRTP_MASTER_KEY_KEY_LEN 16
#define SRTP_MASTER_KEY_SALT_LEN 14
#define ICE_USERNAME "EJYWWCUDJQLTXTNQRXEJ"
#define ICE_USERNAME_LENGTH 20
#define ICE_PASSWORD "SKYKPPYLTZOAVCLTGHDUODANRKSPOVQVKXJULOGG"
#define ICE_PASSWORD_LENGTH 40
#define SRTP_AUTH_KEY_LENGTH 10
#define VP8_TIMESTAMP_SPACING 3000


// Minimal 12 byte RTP header structure. No facility for extensions etc.
class RtpHeader {
	
	public:
	
		uint8_t Version = RTP_VERSION;   // 2 bits.
		uint8_t PaddingFlag = 0;        // 1 bit.
		uint8_t HeaderExtensionFlag = 0; // 1 bit.
		uint8_t CSRCCount = 0;           // 4 bits.
		uint8_t MarkerBit = 0;           // 1 bit.
		uint8_t PayloadType = 0;         // 7 bits.
		uint16_t SeqNum = 0;             // 16 bits.
		uint32_t Timestamp = 0;          // 32 bits.
		uint32_t SyncSource = 0;         // 32 bits.

		void Serialise(uint8_t** buf)
		{
			*buf = (uint8_t*)calloc(RTP_HEADER_LENGTH, 1);
			*(*buf) = (Version << 6 & 0xC0) | (PaddingFlag << 5 & 0x20) | (HeaderExtensionFlag << 4 & 0x10) | (CSRCCount & 0x0f);
			*(*buf + 1) = (MarkerBit << 7 & 0x80) | (PayloadType & 0x7f);
			*(*buf + 2) = SeqNum >> 8 & 0xff;
			*(*buf + 3) = SeqNum & 0xff;
			*(*buf + 4) = Timestamp >> 24 & 0xff;
			*(*buf + 5) = Timestamp >> 16 & 0xff;
			*(*buf + 6) = Timestamp >> 8 & 0xff;
			*(*buf + 7) = Timestamp & 0xff;
			*(*buf + 8) = SyncSource >> 24 & 0xff;
			*(*buf + 9) = SyncSource >> 16 & 0xff;
			*(*buf + 10) = SyncSource >> 8 & 0xff;
			*(*buf + 11) = SyncSource & 0xff;
		}
};


// STUN message types needed for this example
enum class StunMessageTypes : uint16_t {
	
	BindingRequest = 0x0001,
	BindingSuccessResponse = 0x0101,
	BindingErrorResponse = 0x0111,
};


// STUN attribute types needed for this example
enum class StunAttributeTypes : uint16_t {
	
	Username = 0x0006,
	Password = 0x0007,
	MessageIntegrity = 0x0008,
	Priority = 0x0024,
	XORMappedAddress = 0x0020,
	UseCandidate = 0x0025,
	FingerPrint = 0x8028,
};


// Minimal STUN attribute
class StunAttribute {
	
	public:
	
		static const int HEADER_LENGTH = 4;
		static const int XORMAPPED_ADDRESS_ATTRIBUTE_LENGTH = 8;
		static const int MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH = 20;
		static const int FINGERPRINT_ATTRIBUTE_CRC32_LENGTH = 4;
		static const int FINGERPRINT_XOR = 0x5354554e;

		uint16_t Type = 0;            // 16 bits.
		uint16_t Length = 0;          // 16 bits.
		std::vector<uint8_t> Value;   // Variable length.
		uint16_t Padding = 0;         // Attributes start on 32 bit word boundaries. 

		StunAttribute() {}

		StunAttribute(StunAttributeTypes type, std::vector<uint8_t> val) {
			Type = (uint16_t)type;
			Length = val.size();
			Padding = (Length % 4 != 0) ? 4 - (Length % 4) : 0;
			Value = val;
		}


		void Deserialise(const uint8_t* buffer, int bufferLength) {
			
			if (bufferLength < HEADER_LENGTH) {
				throw std::runtime_error("Could not deserialise STUN attribute, buffer too small.");
			}
			else {
				Type = ((buffer[0] << 8) & 0xff00) + buffer[1];
				Length = ((buffer[2] << 8) & 0xff00) + buffer[3];
				Padding = (Length % 4 != 0) ? 4 - (Length % 4) : 0;
				Value.resize(Length);
				memcpy(Value.data(), buffer + HEADER_LENGTH, Length);
			}
		}


		static StunAttribute GetXorMappedAddrAttribute(uint8_t addrFamily, uint16_t port, uint32_t address, const uint8_t * magicCookie) {
			
			std::vector<uint8_t> val(XORMAPPED_ADDRESS_ATTRIBUTE_LENGTH);

			val[0] = 0x00;
			val[1] = addrFamily == AF_INET ? 0x01 : 0x02;
			val[2] = (port >> 8) & 0xff ^ *magicCookie;
			val[3] = port & 0xff ^ *(magicCookie + 1);
			val[4] = (address >> 24) & 0xff ^ *magicCookie;
			val[5] = (address >> 16) & 0xff ^ *(magicCookie + 1);
			val[6] = (address >> 8) & 0xff ^ *(magicCookie + 2);
			val[7] = address & 0xff ^ *(magicCookie + 3);

			StunAttribute att(StunAttributeTypes::XORMappedAddress, val);
			return att;
		}


		static StunAttribute GetMessageIntegrityAttribute() {
			
			std::vector<uint8_t> emptyHmac(MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH, 0x00);
			StunAttribute att(StunAttributeTypes::MessageIntegrity, emptyHmac);
			return att;
		}


		static StunAttribute GetFingerprintAttribute() {
			std::vector<uint8_t> emptyFingerprint(FINGERPRINT_ATTRIBUTE_CRC32_LENGTH, 0x00);
			StunAttribute att(StunAttributeTypes::FingerPrint, emptyFingerprint);
			return att;
		}
};


class StunMessage {
	
	public:
	
		static const int HEADER_LENGTH = 20;
		static const int TRANSACTION_ID_LENGTH = 12;
		static const uint8_t STUN_INITIAL_BYTE_MASK = 0xc0;

		// Header fields.
		uint16_t Type = 0;                              // 12 bits.
		uint16_t Length = 0;                            // 18 bits.
		uint8_t TransactionID[TRANSACTION_ID_LENGTH];   // 96 bits.

		std::vector<StunAttribute> Attributes;

		StunMessage() {}

		StunMessage(StunMessageTypes messageType) {
			Type = (uint16_t)messageType;
		}


		void AddXorMappedAttribute(uint8_t addrFamily, uint16_t port, uint32_t address, const uint8_t* magicCookie) {
			auto xorAddrAttribute = StunAttribute::GetXorMappedAddrAttribute(addrFamily, port, address, magicCookie);
			Attributes.push_back(xorAddrAttribute);
		}

		// Add as the second last attribute
		void AddHmacAttribute(const char* icePwd, int icePwdLen) {
			
			auto hmacAttribute = StunAttribute::GetMessageIntegrityAttribute();
			Attributes.push_back(hmacAttribute);

			uint8_t* respBuffer = nullptr;

			// The message integrity attribute doesn't get included in the HMAC.
			int respBufferLength = Serialise(&respBuffer) - StunAttribute::HEADER_LENGTH - StunAttribute::MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH;

			//std::cout << "HMAC input: " << HexStr(respBuffer, respBufferLength) << std::endl;

			UINT hmacLength = StunAttribute::MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH;
			std::vector<uint8_t> hmac(StunAttribute::MESSAGE_INTEGRITY_ATTRIBUTE_HMAC_LENGTH);

			HMAC(EVP_sha1(), icePwd, icePwdLen, respBuffer, respBufferLength, hmac.data(), &hmacLength);

			free(respBuffer);

			Attributes.back().Value = hmac;
		}

		// Add as the last attribute
		void AddFingerprintAttribute() {
			
			auto fingerprintAttribute = StunAttribute::GetFingerprintAttribute();
			Attributes.push_back(fingerprintAttribute);

			uint8_t* respBuffer = nullptr;

			// The fingerprint attribute doesn't get included in the CRC.
			int respBufferLength = Serialise(&respBuffer) - StunAttribute::HEADER_LENGTH - StunAttribute::FINGERPRINT_ATTRIBUTE_CRC32_LENGTH;

			//std::cout << "Fingerprint input: " << HexStr(respBuffer, respBufferLength) << std::endl;

			// Set the last 4 bytes with the fingerprint CRC.
			uint32_t crc = crc32(0L, Z_NULL, 0);
			crc = crc32(crc, (const unsigned char*)respBuffer, respBufferLength);
			crc = crc ^ StunAttribute::FINGERPRINT_XOR;

			auto crcBuffer = Attributes.back().Value.data();

			crcBuffer[0] = (crc >> 24) & 0xff;
			crcBuffer[1] = (crc >> 16) & 0xff;
			crcBuffer[2] = (crc >> 8) & 0xff;
			crcBuffer[3] = crc & 0xff;
		}


		int Serialise(uint8_t** buf) {
		
			static constexpr const uint8_t MAGIC_COOKIE_BYTES[] = { 0x21, 0x12, 0xA4, 0x42 };
			uint16_t messageLength = 0;
			for (auto att : Attributes) {
				messageLength += att.Length + att.Padding + StunAttribute::HEADER_LENGTH;
			}

			*buf = (uint8_t*)calloc(messageLength + HEADER_LENGTH, 1);

			// Serialise header.
			*(*buf) = (Type >> 8) & 0x03;
			*(*buf + 1) = Type & 0xff;
			*(*buf + 2) = (messageLength >> 8) & 0xff;
			*(*buf + 3) = messageLength & 0xff;
			
			// Magic Cookie
			*(*buf + 4) = MAGIC_COOKIE_BYTES[0];
			*(*buf + 5) = MAGIC_COOKIE_BYTES[1];
			*(*buf + 6) = MAGIC_COOKIE_BYTES[2];
			*(*buf + 7) = MAGIC_COOKIE_BYTES[3];
			
			// TransactionID.
			int bufPosn = 8;
			while (bufPosn < HEADER_LENGTH) {
				*(*buf + bufPosn) = TransactionID[bufPosn - 8];
				bufPosn++;
			}

			// Serialise attributes.
			bufPosn = HEADER_LENGTH;
			for (auto att : Attributes) {
			
				*(*buf + bufPosn++) = (att.Type) >> 8 & 0xff;
				*(*buf + bufPosn++) = att.Type & 0xff;
				*(*buf + bufPosn++) = (att.Length) >> 8 & 0xff;
				*(*buf + bufPosn++) = att.Length & 0xff;
				memcpy(*buf + bufPosn, att.Value.data(), att.Length);
				bufPosn += att.Length + att.Padding;
			}

			return messageLength + HEADER_LENGTH;
		}

		void Deserialise(const uint8_t* buffer, int bufferLength) {
			
			if ((buffer[0] & STUN_INITIAL_BYTE_MASK) != 0) {
				throw std::runtime_error("Could not deserialise STUN header, invalid first byte.");
			}
			else if (bufferLength < HEADER_LENGTH) {
				throw std::runtime_error("Could not deserialise STUN header, buffer too small.");
			}
			else {
				Type = ((buffer[0] << 8) & 0xff00) + buffer[1];
				Length = ((buffer[2] << 8) & 0xff00) + buffer[3];
				memcpy(TransactionID, &buffer[8], TRANSACTION_ID_LENGTH);
			}

			int bufPosn = HEADER_LENGTH;

			while (bufPosn < bufferLength) {
				
				StunAttribute att;
				att.Deserialise(buffer + bufPosn, bufferLength - bufPosn);
				Attributes.push_back(att);

				bufPosn += att.HEADER_LENGTH + att.Length + att.Padding;
			}
		}
};


void SendStunBindingResponse(const char *icePwd, int icePwdLen, int rtpSocket, StunMessage & bindingRequest, sockaddr_in client) {
	
	StunMessage stunBindingResp(StunMessageTypes::BindingSuccessResponse);
	std::copy(bindingRequest.TransactionID, bindingRequest.TransactionID + StunMessage::TRANSACTION_ID_LENGTH, stunBindingResp.TransactionID);

	// Add required attributes.
	static constexpr const uint8_t MAGIC_COOKIE_BYTES[] = { 0x21, 0x12, 0xA4, 0x42 };
	stunBindingResp.AddXorMappedAttribute(client.sin_family, ntohs(client.sin_port), ntohl(client.sin_addr.s_addr), MAGIC_COOKIE_BYTES);
	stunBindingResp.AddHmacAttribute(icePwd, icePwdLen);
	stunBindingResp.AddFingerprintAttribute();

	uint8_t* respBuffer = nullptr;
	int respBufferLength = stunBindingResp.Serialise(&respBuffer);

	printf("Sending STUN response packet, length %d.\n", respBufferLength);

	sendto(rtpSocket, (const char*)respBuffer, respBufferLength, 0, (sockaddr*)&client, sizeof(client));

	free(respBuffer);
}


void eva_srtp_init() {
	
	srtp_init();
}


int eva_send_stun_binding_response(const char *ice_pwd, int ice_pwd_len, int rtpSocket, uint8_t *recvBuffer, int recvResult, struct sockaddr_in clientAddr) {
	
	// STUN packet.
	//printf("STUN packet received.\n");
	StunMessage stunMsg;
	stunMsg.Deserialise(recvBuffer, recvResult);

	// Send binding success response.
	if (stunMsg.Type == (uint16_t)StunMessageTypes::BindingRequest) {
		SendStunBindingResponse(ice_pwd, ice_pwd_len, rtpSocket, stunMsg, clientAddr);
	}

	return 0;
}


srtp_t *eva_srtp_create(unsigned char *dtls_buffer) {
	
	// SRTP variables.
	unsigned char client_write_key[SRTP_MASTER_KEY_KEY_LEN + SRTP_MASTER_KEY_SALT_LEN];
	unsigned char server_write_key[SRTP_MASTER_KEY_KEY_LEN + SRTP_MASTER_KEY_SALT_LEN];
	size_t keyMaterialOffset = 0;
	
	memcpy(&client_write_key[0], &dtls_buffer[keyMaterialOffset], SRTP_MASTER_KEY_KEY_LEN);
	keyMaterialOffset += SRTP_MASTER_KEY_KEY_LEN;
	memcpy(&server_write_key[0], &dtls_buffer[keyMaterialOffset], SRTP_MASTER_KEY_KEY_LEN);
	keyMaterialOffset += SRTP_MASTER_KEY_KEY_LEN;
	memcpy(&client_write_key[SRTP_MASTER_KEY_KEY_LEN], &dtls_buffer[keyMaterialOffset], SRTP_MASTER_KEY_SALT_LEN);
	keyMaterialOffset += SRTP_MASTER_KEY_SALT_LEN;
    memcpy(&server_write_key[SRTP_MASTER_KEY_KEY_LEN], &dtls_buffer[keyMaterialOffset], SRTP_MASTER_KEY_SALT_LEN);

	srtp_policy_t *srtpPolicy = new srtp_policy_t();
	srtp_t *srtpSession = new srtp_t();

	srtp_crypto_policy_set_rtp_default(&srtpPolicy->rtp);
	srtp_crypto_policy_set_rtcp_default(&srtpPolicy->rtcp);

    // Init transmit direction
	srtpPolicy->key = server_write_key;
    srtpPolicy->ssrc.value = 0;
    srtpPolicy->window_size = 128;
    srtpPolicy->allow_repeat_tx = 0;
    srtpPolicy->ssrc.type = ssrc_any_outbound;
    srtpPolicy->next = NULL;

	auto err = srtp_create(srtpSession, srtpPolicy);
	if (err != srtp_err_status_ok) {

		
    }

	return srtpSession;
}


int eva_send_rtp_sample(int socket, struct sockaddr_in dst, srtp_t *srtpSession, BYTE *frameData, size_t frameLength, uint32_t ssrc, uint32_t timestamp, uint16_t* seqNum) {
	
	int check = 1;
	uint16_t pktSeqNum = *seqNum;

	for (UINT offset = 0; offset < frameLength;) {

		bool isLast = ((offset + RTP_MAX_PAYLOAD) >= frameLength); // Note can be first and last packet at same time if a small frame.
		UINT payloadLength = !isLast ? RTP_MAX_PAYLOAD : frameLength - offset;

		RtpHeader rtpHeader;
		rtpHeader.SyncSource = ssrc;
		rtpHeader.SeqNum = pktSeqNum++;
		rtpHeader.Timestamp = timestamp;
		rtpHeader.MarkerBit = (isLast) ? 1 : 0;    // Marker bit gets set on last packet in frame.
		rtpHeader.PayloadType = RTP_PAYLOAD_ID;

		uint8_t* hdrSerialised = NULL;
		rtpHeader.Serialise(&hdrSerialised);

		int rtpPacketSize = RTP_HEADER_LENGTH + VP8_RTP_HEADER_LENGTH + payloadLength;
		int srtpPacketSize = rtpPacketSize + SRTP_AUTH_KEY_LENGTH;
		uint8_t* rtpPacket = (uint8_t*)malloc(srtpPacketSize);
		memcpy(rtpPacket, hdrSerialised, RTP_HEADER_LENGTH);
		rtpPacket[RTP_HEADER_LENGTH] = (offset == 0) ? 0x10 : 0x00 ; // Set the VP8 header byte.
		memcpy(&rtpPacket[RTP_HEADER_LENGTH + VP8_RTP_HEADER_LENGTH], &frameData[offset], payloadLength);

		//printf("Sending RTP packet, length %d.\n", rtpPacketSize);

		auto protRes = srtp_protect(*srtpSession, rtpPacket, &rtpPacketSize);
		if (protRes != srtp_err_status_ok) {
			printf("SRTP protect failed with error code %d.\n", protRes);
			check = 0;
		}

		sendto(socket, (const char*)rtpPacket, srtpPacketSize, 0, (sockaddr*)&dst, sizeof(dst));

		offset += payloadLength;

		free(hdrSerialised);
		free(rtpPacket);
	}

	*seqNum = pktSeqNum;

	return check;
}








