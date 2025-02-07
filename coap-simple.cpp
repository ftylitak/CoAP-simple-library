#include "coap-simple.h"
#include "Arduino.h"

#define LOGGING

CoapPacket::CoapPacket() : 
  	type(COAP_CON),
    code(COAP_GET),
    token(NULL),
	tokenlen(0),
	payload(NULL),
	payloadlen(0),
	messageid(0),
    contentType(COAP_NONE),
    query(NULL),
    querylen(0), 
    optionnum(0)
{}

void CoapPacket::addOption(uint8_t number, uint8_t length, uint8_t *opt_payload)
{
    options[optionnum].number = number;
    options[optionnum].length = length;
    options[optionnum].buffer = opt_payload;

    ++optionnum;
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
    size_t idx = 0;
    for (size_t i = 0; i < strlen(url); i++) {
        if (url[i] == '/') {
			addOption(COAP_URI_PATH, i-idx, (uint8_t *)(url + idx));
            idx = i + 1;
        }
    }

    if (idx <= strlen(url)) {
		addOption(COAP_URI_PATH, strlen(url)-idx, (uint8_t *)(url + idx));
    }
}

String CoapPacket::toString() 
{
    String result("");

    result += "type: ";
    result += type;
    result += ", code: ";
    result += code;
    result += ", messageid: ";
    result += messageid;
    result += ", contentType: ";
    result += contentType;

    result += ", tokenlen: ";
    result += tokenlen;	

    if(token) {
        result += ", token: ";
        result += (char *)token;
    }

    result += ", payloadlen: ";
    result += payloadlen;

    if(payload) {
        result += ", payload: ";
        result += (char *)payload;
    }

    result += ", querylen: ";
    result += querylen;

    if(query) {
        result += ", query: ";
        result += (char *)query;
    }

    return result;
}

Coap::Coap(
    UDP& udp
) {
    _udp = &udp;
}

bool Coap::start() {
    start(COAP_DEFAULT_PORT);
    return true;
}

bool Coap::start(int port) {
    return _udp->begin(port);
}

void Coap::stop() {
    _udp->stop();
}

uint16_t Coap::sendPacket(CoapPacket &packet, IPAddress ip) {
    return sendPacket(packet, ip, COAP_DEFAULT_PORT);
}

uint16_t Coap::sendPacket(CoapPacket &packet, const IPAddress &ip, int port) {
    uint8_t buffer[BUF_MAX_SIZE];
    uint8_t *p = buffer;
    uint16_t running_delta = 0;
    uint16_t packetSize = 0;

    memset(buffer, 0, BUF_MAX_SIZE);

    // make coap packet base header
    *p = 0x01 << 6;
    *p |= (packet.type & 0x03) << 4;
    *p++ |= (packet.tokenlen & 0x0F);
    *p++ = packet.code;
    *p++ = (packet.messageid >> 8);
    *p++ = (packet.messageid & 0xFF);
    p = buffer + COAP_HEADER_SIZE;
    packetSize += 4;

    // make token
    if (packet.token != NULL && packet.tokenlen <= 0x0F) {
        memcpy(p, packet.token, packet.tokenlen);
        p += packet.tokenlen;
        packetSize += packet.tokenlen;
    }

    // make option header
    for (int i = 0; i < packet.optionnum; i++)  {
        uint32_t optdelta;
        uint8_t len, delta;

        if (packetSize + 5 + packet.options[i].length >= BUF_MAX_SIZE) {
            return 0;
        }
        optdelta = packet.options[i].number - running_delta;
        COAP_OPTION_DELTA(optdelta, &delta);
        COAP_OPTION_DELTA((uint32_t)packet.options[i].length, &len);

        *p++ = (0xFF & (delta << 4 | len));
        if (delta == 13) {
            *p++ = (optdelta - 13);
            packetSize++;
        } else if (delta == 14) {
            *p++ = ((optdelta - 269) >> 8);
            *p++ = (0xFF & (optdelta - 269));
            packetSize+=2;
        } 
        
        if (len == 13) {
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
        running_delta = packet.options[i].number;
    }

    // make payload
    if (packet.payloadlen > 0) {
        if ((packetSize + 1 + packet.payloadlen) >= BUF_MAX_SIZE) {
            return 0;
        }
        *p++ = 0xFF;
        memcpy(p, packet.payload, packet.payloadlen);
        packetSize += 1 + packet.payloadlen;
    }

    bool udpOperationStatus = _udp->beginPacket(ip, port);

    if(udpOperationStatus)
        udpOperationStatus &= (_udp->write(buffer, packetSize) == packetSize);
    else
        Serial.println("Begin packet failed");

    if(udpOperationStatus) 
        udpOperationStatus &= _udp->endPacket();
    else
        Serial.println("Write bytes failed");

    if(udpOperationStatus)
        return packet.messageid;
    else 
    {
        Serial.println("End packet failed");
        return 0;
    }
}

uint16_t Coap::get(const IPAddress &ip, int port, const char *url) {
    return send(ip, port, url, COAP_CON, COAP_GET, NULL, 0, NULL, 0);
}

uint16_t Coap::put(const IPAddress &ip, int port, const char *url, char *payload) {
    return send(ip, port, url, COAP_CON, COAP_PUT, NULL, 0, (uint8_t *)payload, strlen(payload));
}

uint16_t Coap::put(const IPAddress &ip, int port, const char *url, char *payload, uint16_t payloadlen) {
    return send(ip, port, url, COAP_CON, COAP_PUT, NULL, 0, (uint8_t *)payload, payloadlen);
}

uint16_t Coap::post(const IPAddress &ip, int port, const char *url, char *payload) {
    return send(ip, port, url, COAP_CON, COAP_POST, NULL, 0, (uint8_t *)payload, strlen(payload));
}

uint16_t Coap::post(const IPAddress &ip, int port, const char *url, char *payload, uint16_t payloadlen) {
    return send(ip, port, url, COAP_CON, COAP_POST, NULL, 0, (uint8_t *)payload, payloadlen);
}

uint16_t Coap::post(const IPAddress &ip, int port, const char *url, char *payload, uint16_t payloadlen, char *queryOption) {
    return send(ip, port, url, COAP_CON, COAP_POST, NULL, 0, (uint8_t *)payload, payloadlen, COAP_NONE, (uint8_t *)queryOption, strlen(queryOption));
}

uint16_t Coap::post(const IPAddress &ip, int port, const char *url, char *payload, uint16_t payloadlen, char *queryOption, uint16_t queryOptionlen) {
    return send(ip, port, url, COAP_CON, COAP_POST, NULL, 0, (uint8_t *)payload, payloadlen, COAP_NONE, (uint8_t *)queryOption, queryOptionlen);
}

uint16_t Coap::send(const IPAddress &ip, int port, const char *url, COAP_TYPE type, COAP_METHOD method, uint8_t *token, uint8_t tokenlen, uint8_t *payload, uint16_t payloadlen) {
    return send(ip, port, url, type, method, NULL, 0, (uint8_t *)payload, payloadlen, COAP_NONE);
}

uint16_t Coap::send(const IPAddress &ip, int port, const char *url, COAP_TYPE type, COAP_METHOD method, uint8_t *token, uint8_t tokenlen, uint8_t *payload, uint16_t payloadlen, COAP_CONTENT_TYPE content_type){
    return send(ip, port, url, type, method, NULL, 0, (uint8_t *)payload, payloadlen, content_type, NULL, 0); 
}

uint16_t Coap::send(const IPAddress &ip, int port, const char *url, COAP_TYPE type, COAP_METHOD method, uint8_t *token, uint8_t tokenlen, uint8_t *payload, uint16_t payloadlen, COAP_CONTENT_TYPE content_type, uint8_t *queryOption, uint16_t queryOptionlen) {

    // make packet
    CoapPacket packet;

    packet.type = type;
    packet.code = method;
    packet.token = token;
    packet.tokenlen = tokenlen;
    packet.payload = payload;
    packet.payloadlen = payloadlen;
    packet.contentType = content_type;
    packet.query = queryOption;
    packet.querylen = queryOptionlen;

    return sendEx(ip, port, url, packet);
}

uint16_t Coap::sendEx(const IPAddress &ip, int port, const char *url, CoapPacket &packet)
{
    packet.optionnum = 0;
    packet.messageid = rand();
    packet.setUriHost(ip);
    packet.setUriPath(url);

    uint8_t optionBuffer[2] {0};
    if (packet.contentType != COAP_NONE) {
        optionBuffer[0] = ((uint16_t)packet.contentType & 0xFF00) >> 8;
        optionBuffer[1] = ((uint16_t)packet.contentType & 0x00FF) ;
        packet.addOption(COAP_CONTENT_FORMAT, 2, optionBuffer);
    }

    if(packet.query && packet.querylen > 0) {
        packet.addOption(COAP_URI_QUERY, packet.querylen, packet.query);
    }

    return sendPacket(packet, ip, port);
}

int Coap::parseOption(CoapOption *option, uint16_t *running_delta, uint8_t **buf, size_t buflen) {
    uint8_t *p = *buf;
    uint8_t headlen = 1;
    uint16_t len, delta;

    if (buflen < headlen) return -1;

    delta = (p[0] & 0xF0) >> 4;
    len = p[0] & 0x0F;

    if (delta == 13) {
        headlen++;
        if (buflen < headlen) return -1;
        delta = p[1] + 13;
        p++;
    } else if (delta == 14) {
        headlen += 2;
        if (buflen < headlen) return -1;
        delta = ((p[1] << 8) | p[2]) + 269;
        p+=2;
    } else if (delta == 15) return -1;

    if (len == 13) {
        headlen++;
        if (buflen < headlen) return -1;
        len = p[1] + 13;
        p++;
    } else if (len == 14) {
        headlen += 2;
        if (buflen < headlen) return -1;
        len = ((p[1] << 8) | p[2]) + 269;
        p+=2;
    } else if (len == 15)
        return -1;

    if ((p + 1 + len) > (*buf + buflen))  return -1;
    option->number = delta + *running_delta;
    option->buffer = p+1;
    option->length = len;
    *buf = p + 1 + len;
    *running_delta += delta;

    return 0;
}

bool Coap::loop() {

    uint8_t buffer[BUF_MAX_SIZE];
    int32_t packetlen = _udp->parsePacket();

    while (packetlen > 0) {
        packetlen = _udp->read(buffer, packetlen >= BUF_MAX_SIZE ? BUF_MAX_SIZE : packetlen);

        // parse coap packet header
        if (packetlen < COAP_HEADER_SIZE || (((buffer[0] & 0xC0) >> 6) != 1)) {
            packetlen = _udp->parsePacket();
            continue;
        }

        CoapPacket packet;

        packet.type = (buffer[0] & 0x30) >> 4;
        packet.tokenlen = buffer[0] & 0x0F;
        packet.code = buffer[1];
        packet.messageid = 0xFF00 & (buffer[2] << 8);
        packet.messageid |= 0x00FF & buffer[3];

        if (packet.tokenlen == 0)  packet.token = NULL;
        else if (packet.tokenlen <= 8)  packet.token = buffer + 4;
        else {
            packetlen = _udp->parsePacket();
            continue;
        }

        // parse packet options/payload
        if (COAP_HEADER_SIZE + packet.tokenlen < packetlen) {
            int optionIndex = 0;
            uint16_t delta = 0;
            uint8_t *end = buffer + packetlen;
            uint8_t *p = buffer + COAP_HEADER_SIZE + packet.tokenlen;
            while(optionIndex < MAX_OPTION_NUM && *p != 0xFF && p < end) {
                if (0 != parseOption(&packet.options[optionIndex], &delta, &p, end-p))
                    return false;
                optionIndex++;
            }
            packet.optionnum = optionIndex;

            if (p+1 < end && *p == 0xFF) {
                packet.payload = p+1;
                packet.payloadlen = end-(p+1);
            } else {
                packet.payload = NULL;
                packet.payloadlen= 0;
            }
        }

        if (packet.type == COAP_ACK) {
            // call response function
            resp(packet, _udp->remoteIP(), _udp->remotePort());

        } else {
            
            String url = "";
            // call endpoint url function
            for (int i = 0; i < packet.optionnum; i++) {
                if (packet.options[i].number == COAP_URI_PATH && packet.options[i].length > 0) {
                    char urlname[packet.options[i].length + 1];
                    memcpy(urlname, packet.options[i].buffer, packet.options[i].length);
                    urlname[packet.options[i].length] = '\0';
                    if(url.length() > 0)
                      url += "/";
                    url += urlname;
                }
            }        

            if (!uri.find(url)) {
                sendResponse(_udp->remoteIP(), _udp->remotePort(), packet.messageid, NULL, 0,
                        COAP_NOT_FOUNT, COAP_NONE, NULL, 0);
            } else {
                uri.find(url)(packet, _udp->remoteIP(), _udp->remotePort());
            }
        }

        /* this type check did not use.
        if (packet.type == COAP_CON) {
            // send response 
             sendResponse(_udp->remoteIP(), _udp->remotePort(), packet.messageid);
        }
         */

        // next packet
        packetlen = _udp->parsePacket();
    }

    return true;
}

uint16_t Coap::sendResponse(const IPAddress &ip, int port, uint16_t messageid) {
    return sendResponse(ip, port, messageid, NULL, 0, COAP_CONTENT, COAP_TEXT_PLAIN, NULL, 0);
}

uint16_t Coap::sendResponse(const IPAddress &ip, int port, uint16_t messageid, char *payload) {
    return sendResponse(ip, port, messageid, payload, strlen(payload), COAP_CONTENT, COAP_TEXT_PLAIN, NULL, 0);
}

uint16_t Coap::sendResponse(const IPAddress &ip, int port, uint16_t messageid, char *payload, uint16_t payloadlen) {
    return sendResponse(ip, port, messageid, payload, payloadlen, COAP_CONTENT, COAP_TEXT_PLAIN, NULL, 0);
}


uint16_t Coap::sendResponse(const IPAddress &ip, int port, uint16_t messageid, char *payload, uint16_t payloadlen,
                COAP_RESPONSE_CODE code, COAP_CONTENT_TYPE contentType, uint8_t *token, int tokenlen) {
    // make packet
    CoapPacket packet;

    packet.type = COAP_ACK;
    packet.code = code;
    packet.token = token;
    packet.tokenlen = tokenlen;
    packet.payload = (uint8_t *)payload;
    packet.payloadlen = payloadlen;
    packet.optionnum = 0;
    packet.messageid = messageid;

    // if more options?
    uint8_t optionBuffer[2] = {0};
    optionBuffer[0] = ((uint16_t)contentType & 0xFF00) >> 8;
    optionBuffer[1] = ((uint16_t)contentType & 0x00FF) ;
	packet.addOption(COAP_CONTENT_FORMAT, 2, optionBuffer);

    return sendPacket(packet, ip, port);
}
