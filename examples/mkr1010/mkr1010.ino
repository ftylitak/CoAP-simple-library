
#include <SPI.h>
#include <WiFiNINA.h>
#include <WiFiUdp.h>

#include <coap-simple.h>

int status = WL_IDLE_STATUS;

#include "arduino_secrets.h" 
///////please enter your sensitive data in the Secret tab/arduino_secrets.h
char ssid[] = SECRET_SSID;        // your network SSID (name)
char pass[] = SECRET_PASS;    // your network password (use for WPA, or use as key for WEP)

WiFiUDP Udp;
Coap coap(Udp);

// CoAP client response callback
void callback_response(CoapPacket &packet, IPAddress ip, int port) {
  Serial.println("[Coap Response got]");

  char p[packet.payloadLen + 1];
  memcpy(p, packet.payload, packet.payloadLen);
  p[packet.payloadLen] = NULL;

  Serial.println(p);
}


void setup() {
  //Initialize serial and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  // check for the WiFi module:
  if (WiFi.status() == WL_NO_MODULE) {
    Serial.println("Communication with WiFi module failed!");
    // don't continue
    while (true);
  }

  String fv = WiFi.firmwareVersion();
  if (fv < "1.0.0") {
    Serial.println("Please upgrade the firmware");
  }

  // attempt to connect to Wifi network:
  while (status != WL_CONNECTED) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);
    // Connect to WPA/WPA2 network. Change this line if using open or WEP network:
    status = WiFi.begin(ssid, pass);

    // wait 10 seconds for connection:
    delay(10000);
  }
  Serial.println("Connected to wifi");
  printWifiStatus();

  Serial.print("\nStarting coap...");
  coap.response(callback_response);

  // start coap server/client
  bool status = coap.start();

  Serial.println(status);
}

void loop() {

  // send GET or PUT coap request to CoAP server.
  // To test, use libcoap, microcoap server...etc
  
  sendPostRequestSimple();
  coap.loop();

  delay(5000);

  sendPostRequestCustom();
  coap.loop();

  delay(10000);
}

void sendPostRequestSimple() {
  Serial.print("Send Simple Request...");
  char *payload = "{\"v\":1}";
  char *url = "meter";
  char *query = "auth=abcd123";
  
  //This method will post the above information with the defalut content type which will result to octet array payload
  //Effective URL based on configuration: coap://127.0.0.1/meter?auth=abcd123
  int msgid =  coap.post(IPAddress(127, 0, 0, 1), 5683, url, payload, strlen(url), query, strlen(query));
  Serial.println(msgid);
}

void sendPostRequestCustom() {
  Serial.print("Send Custom Request...");
  char *payload = "{\"v\":1}";
  char *url = "meter";
  char *query = "auth=abcd123";
  
  //This method will post the above information with the defalut content type which will result to octet array payload
  //Effective URL based on configuration: coap://127.0.0.1/meter?auth=abcd123
  CoapPacket packet;
  packet.code = COAP_POST;
  packet.payload = (uint8_t*)payload;
  packet.payloadLen = strlen(payload);
  packet.contentType = COAP_TEXT_PLAIN;
  packet.query = (uint8_t*)query;
  packet.queryLen = strlen(query);

  int msgid = coap.sendEx(IPAddress(127, 0, 0, 1), 5683, url, packet);

  Serial.println(msgid);
}

void printWifiStatus() {
  // print the SSID of the network you're attached to:
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print your board's IP address:
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);

  // print the received signal strength:
  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI):");
  Serial.print(rssi);
  Serial.println(" dBm");
}