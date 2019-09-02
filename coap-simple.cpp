#include "coap-simple.h"
#include "Arduino.h"

#define LOGGING

CoapPacket::CoapPacket() : 
  	type(COAP_CON),
    code(COAP_GET),
    token(NULL),
	tokenLen(0),
	payload(NULL),
	payloadLen(0),
	messageId(0),
    contentType(COAP_NONE),
    optionNum(0),
    query(NULL),
    queryLen(0)
{}

void CoapPacket::addOption(uint8_t number, uint8_t length, uint8_t *optPayload)
{
    options[optionNum].number = number;
    options[optionNum].length = length;
    options[optionNum].buffer = optPayload;

    ++optionNum;
}

void CoapPacket::setUriHost(const IPAddress &address)
{
    // use URI_HOST UIR_PATH
    String ipaddress = String(address[0]) + String(".") + String(address[1]) + String(".") + String(address[2]) + String(".") + String(address[3]); 
	addOption(COAP_URI_HOST, ipaddress.length(), (uint8_t *)ipaddress.c_str());
}

void CoapPacket::setUriPath(const char* url)
{
    // parse url
    int idx = 0;
    for (int i = 0; i < strlen(url); i++) {
        if (url[i] == '/') {
			addOption(COAP_URI_PATH, i-idx, (uint8_t *)(url + idx));
            idx = i + 1;
        }
    }

    if (idx <= strlen(url)) {
		addOption(COAP_URI_PATH, strlen(url)-idx, (uint8_t *)(url + idx));
    }
}

Coap::Coap(
    UDP& udp
) {
    udp_ = &udp;
}

bool Coap::start() {
    start(COAP_DEFAULT_PORT);
    return true;
}

bool Coap::start(int port) {
    udp_->begin(port);
    return true;
}

uint16_t Coap::sendPacket(CoapPacket &packet, IPAddress ip) {
    return sendPacket(packet, ip, COAP_DEFAULT_PORT);
}

uint16_t Coap::sendPacket(CoapPacket &packet, IPAddress ip, int port) {
    uint8_t buffer[BUF_MAX_SIZE];
    uint8_t *p = buffer;
    uint16_t runningDelta = 0;
    uint16_t packetSize = 0;

    // make coap packet base header
    *p = 0x01 << 6;
    *p |= (packet.type & 0x03) << 4;
    *p++ |= (packet.tokenLen & 0x0F);
    *p++ = packet.code;
    *p++ = (packet.messageId >> 8);
    *p++ = (packet.messageId & 0xFF);
    p = buffer + COAP_HEADER_SIZE;
    packetSize += 4;

    // make token
    if (packet.token != NULL && packet.tokenLen <= 0x0F) {
        memcpy(p, packet.token, packet.tokenLen);
        p += packet.tokenLen;
        packetSize += packet.tokenLen;
    }

    // make option header
    for (int i = 0; i < packet.optionNum; i++)  {
        uint32_t optDelta;
        uint8_t len, delta;

        if (packetSize + 5 + packet.options[i].length >= BUF_MAX_SIZE) {
            return 0;
        }
        optDelta = packet.options[i].number - runningDelta;
        COAP_OPTION_DELTA(optDelta, &delta);
        COAP_OPTION_DELTA((uint32_t)packet.options[i].length, &len);

        *p++ = (0xFF & (delta << 4 | len));
        if (delta == 13) {
            *p++ = (optDelta - 13);
            packetSize++;
        } else if (delta == 14) {
            *p++ = ((optDelta - 269) >> 8);
            *p++ = (0xFF & (optDelta - 269));
            packetSize+=2;
        } if (len == 13) {
            *p++ = (packet.options[i].length - 13);
            packetSize++;
        } else if (len == 14) {
            *p++ = (packet.options[i].length >> 8);
            *p++ = (0xFF & (packet.options[i].length - 269));
            packetSize+=2;
        }

        memcpy(p, packet.options[i].buffer, packet.options[i].length);
        p += packet.options[i].length;
        packetSize += packet.options[i].length + 1;
        runningDelta = packet.options[i].number;
    }

    // make payload
    if (packet.payloadLen > 0) {
        if ((packetSize + 1 + packet.payloadLen) >= BUF_MAX_SIZE) {
            return 0;
        }
        *p++ = 0xFF;
        memcpy(p, packet.payload, packet.payloadLen);
        packetSize += 1 + packet.payloadLen;
    }

    udp_->beginPacket(ip, port);
    udp_->write(buffer, packetSize);
    udp_->endPacket();

    return packet.messageId;
}

uint16_t Coap::get(IPAddress ip, int port, char *url) {
    return send(ip, port, url, COAP_CON, COAP_GET, NULL, 0, NULL, 0);
}

uint16_t Coap::put(IPAddress ip, int port, char *url, char *payload) {
    return send(ip, port, url, COAP_CON, COAP_PUT, NULL, 0, (uint8_t *)payload, strlen(payload));
}

uint16_t Coap::put(IPAddress ip, int port, char *url, char *payload, uint16_t payloadLen) {
    return send(ip, port, url, COAP_CON, COAP_PUT, NULL, 0, (uint8_t *)payload, payloadLen);
}

uint16_t Coap::post(IPAddress ip, int port, char *url, char *payload) {
    return send(ip, port, url, COAP_CON, COAP_POST, NULL, 0, (uint8_t *)payload, strlen(payload));
}

uint16_t Coap::post(IPAddress ip, int port, char *url, char *payload, uint16_t payloadLen) {
    return send(ip, port, url, COAP_CON, COAP_POST, NULL, 0, (uint8_t *)payload, payloadLen);
}

uint16_t Coap::post(IPAddress ip, int port, char *url, char *payload, uint16_t payloadLen, char *queryOption) {
    return send(ip, port, url, COAP_CON, COAP_POST, NULL, 0, (uint8_t *)payload, payloadLen, COAP_NONE, (uint8_t *)queryOption, strlen(queryOption));
}

uint16_t Coap::post(IPAddress ip, int port, char *url, char *payload, uint16_t payloadLen, char *queryOption, uint16_t queryOptionlLen) {
    return send(ip, port, url, COAP_CON, COAP_POST, NULL, 0, (uint8_t *)payload, payloadLen, COAP_NONE, (uint8_t *)queryOption, queryOptionlLen);
}

uint16_t Coap::send(IPAddress ip, int port, char *url, COAP_TYPE type, COAP_METHOD method, uint8_t *token, uint8_t tokenLen, uint8_t *payload, uint16_t payloadLen) {
    return send(ip, port, url, type, method, NULL, 0, (uint8_t *)payload, payloadLen, COAP_NONE);
}

uint16_t Coap::send(IPAddress ip, int port, char *url, COAP_TYPE type, COAP_METHOD method, uint8_t *token, uint8_t tokenLen, uint8_t *payload, uint16_t payloadLen, COAP_CONTENT_TYPE contentType){
    return send(ip, port, url, type, method, NULL, 0, (uint8_t *)payload, payloadLen, contentType, NULL, 0); 
}

uint16_t Coap::send(IPAddress ip, int port, char *url, COAP_TYPE type, COAP_METHOD method, uint8_t *token, uint8_t tokenLen, uint8_t *payload, uint16_t payloadLen, COAP_CONTENT_TYPE contentType, uint8_t *queryOption, uint16_t queryOptionlLen) {

    // make packet
    CoapPacket packet;

    packet.type = type;
    packet.code = method;
    packet.token = token;
    packet.tokenLen = tokenLen;
    packet.payload = payload;
    packet.payloadLen = payloadLen;
    packet.contentType = contentType;
    packet.query = queryOption;
    packet.queryLen = queryOptionlLen;

    return sendEx(ip, port, url, packet);
}

uint16_t Coap::sendEx(IPAddress ip, int port, char *url, CoapPacket &packet)
{
    packet.optionNum = 0;
    packet.messageId = rand();
    packet.setUriHost(ip);
    packet.setUriPath(url);

    	uint8_t optionBuffer[2] {0};
	if (packet.contentType != COAP_NONE) {
		optionBuffer[0] = ((uint16_t)packet.contentType & 0xFF00) >> 8;
		optionBuffer[1] = ((uint16_t)packet.contentType & 0x00FF) ;
		packet.addOption(COAP_CONTENT_FORMAT, 2, optionBuffer);
	}

    if(packet.query && packet.queryLen > 0) {
        packet.addOption(COAP_URI_QUERY, packet.queryLen, packet.query);
    }

    return sendPacket(packet, ip, port);
}

int Coap::parseOption(CoapOption *option, uint16_t *runningDelta, uint8_t **buf, size_t bufLen) {
    uint8_t *p = *buf;
    uint8_t headLen = 1;
    uint16_t len, delta;

    if (bufLen < headLen) return -1;

    delta = (p[0] & 0xF0) >> 4;
    len = p[0] & 0x0F;

    if (delta == 13) {
        headLen++;
        if (bufLen < headLen) return -1;
        delta = p[1] + 13;
        p++;
    } else if (delta == 14) {
        headLen += 2;
        if (bufLen < headLen) return -1;
        delta = ((p[1] << 8) | p[2]) + 269;
        p+=2;
    } else if (delta == 15) return -1;

    if (len == 13) {
        headLen++;
        if (bufLen < headLen) return -1;
        len = p[1] + 13;
        p++;
    } else if (len == 14) {
        headLen += 2;
        if (bufLen < headLen) return -1;
        len = ((p[1] << 8) | p[2]) + 269;
        p+=2;
    } else if (len == 15)
        return -1;

    if ((p + 1 + len) > (*buf + bufLen))  return -1;
    option->number = delta + *runningDelta;
    option->buffer = p+1;
    option->length = len;
    *buf = p + 1 + len;
    *runningDelta += delta;

    return 0;
}

bool Coap::loop() {

    uint8_t buffer[BUF_MAX_SIZE];
    int32_t packetLen = udp_->parsePacket();

    while (packetLen > 0) {
        packetLen = udp_->read(buffer, packetLen >= BUF_MAX_SIZE ? BUF_MAX_SIZE : packetLen);

        CoapPacket packet;

        // parse coap packet header
        if (packetLen < COAP_HEADER_SIZE || (((buffer[0] & 0xC0) >> 6) != 1)) {
            packetLen = udp_->parsePacket();
            continue;
        }

        packet.type = (buffer[0] & 0x30) >> 4;
        packet.tokenLen = buffer[0] & 0x0F;
        packet.code = buffer[1];
        packet.messageId = 0xFF00 & (buffer[2] << 8);
        packet.messageId |= 0x00FF & buffer[3];

        if (packet.tokenLen == 0)  packet.token = NULL;
        else if (packet.tokenLen <= 8)  packet.token = buffer + 4;
        else {
            packetLen = udp_->parsePacket();
            continue;
        }

        // parse packet options/payload
        if (COAP_HEADER_SIZE + packet.tokenLen < packetLen) {
            int optionIndex = 0;
            uint16_t delta = 0;
            uint8_t *end = buffer + packetLen;
            uint8_t *p = buffer + COAP_HEADER_SIZE + packet.tokenLen;
            while(optionIndex < MAX_OPTION_NUM && *p != 0xFF && p < end) {
                packet.options[optionIndex];
                if (0 != parseOption(&packet.options[optionIndex], &delta, &p, end-p))
                    return false;
                optionIndex++;
            }
            packet.optionNum = optionIndex;

            if (p+1 < end && *p == 0xFF) {
                packet.payload = p+1;
                packet.payloadLen = end-(p+1);
            } else {
                packet.payload = NULL;
                packet.payloadLen= 0;
            }
        }

        if (packet.type == COAP_ACK) {
            // call response function
            resp_(packet, udp_->remoteIP(), udp_->remotePort());

        } else {
            
            String url = "";
            // call endpoint url function
            for (int i = 0; i < packet.optionNum; i++) {
                if (packet.options[i].number == COAP_URI_PATH && packet.options[i].length > 0) {
                    char urlName[packet.options[i].length + 1];
                    memcpy(urlName, packet.options[i].buffer, packet.options[i].length);
                    urlName[packet.options[i].length] = NULL;
                    if(url.length() > 0)
                      url += "/";
                    url += urlName;
                }
            }        

            if (!uri_.find(url)) {
                sendResponse(udp_->remoteIP(), udp_->remotePort(), packet.messageId, NULL, 0,
                        COAP_NOT_FOUNT, COAP_NONE, NULL, 0);
            } else {
                uri_.find(url)(packet, udp_->remoteIP(), udp_->remotePort());
            }
        }

        /* this type check did not use.
        if (packet.type == COAP_CON) {
            // send response 
             sendResponse(udp_->remoteIP(), udp_->remotePort(), packet.messageId);
        }
         */

        // next packet
        packetLen = udp_->parsePacket();
    }

    return true;
}

uint16_t Coap::sendResponse(IPAddress ip, int port, uint16_t messageId) {
    return sendResponse(ip, port, messageId, NULL, 0, COAP_CONTENT, COAP_TEXT_PLAIN, NULL, 0);
}

uint16_t Coap::sendResponse(IPAddress ip, int port, uint16_t messageId, char *payload) {
    return sendResponse(ip, port, messageId, payload, strlen(payload), COAP_CONTENT, COAP_TEXT_PLAIN, NULL, 0);
}

uint16_t Coap::sendResponse(IPAddress ip, int port, uint16_t messageId, char *payload, uint16_t payloadLen) {
    return sendResponse(ip, port, messageId, payload, payloadLen, COAP_CONTENT, COAP_TEXT_PLAIN, NULL, 0);
}


uint16_t Coap::sendResponse(IPAddress ip, int port, uint16_t messageId, char *payload, uint16_t payloadLen,
                COAP_RESPONSE_CODE code, COAP_CONTENT_TYPE type, uint8_t *token, int tokenLen) {
    // make packet
    CoapPacket packet;

    packet.type = COAP_ACK;
    packet.code = code;
    packet.token = token;
    packet.tokenLen = tokenLen;
    packet.payload = (uint8_t *)payload;
    packet.payloadLen = payloadLen;
    packet.optionNum = 0;
    packet.messageId = messageId;

    // if more options?
    uint8_t optionBuffer[2] = {0};
    optionBuffer[0] = ((uint16_t)type & 0xFF00) >> 8;
    optionBuffer[1] = ((uint16_t)type & 0x00FF) ;
	packet.addOption(COAP_CONTENT_FORMAT, 2, optionBuffer);

    return sendPacket(packet, ip, port);
}
