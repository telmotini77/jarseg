// JARVIS v0.9 basic ESP32 device. Install WiFi, PubSubClient and ArduinoJson.
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

const char* WIFI_SSID = "YOUR_WIFI";
const char* WIFI_PASSWORD = "YOUR_PASSWORD";
const char* MQTT_HOST = "YOUR_BROKER";
const uint16_t MQTT_PORT = 1883;
const char* DEVICE_ID = "esp32-basic";
const char* CLIENT_ID = "esp32-basic-unique"; // Must be unique for every board.
const char* PREFIX = "jarvis/dev-001";
const int LED_PIN = 2;

WiFiClient wifiClient;
PubSubClient mqtt(wifiClient);
unsigned long lastMqttAttempt = 0;

String topic(const char* suffix) { return String(PREFIX) + "/devices/" + DEVICE_ID + "/" + suffix; }

void publishState() {
  StaticJsonDocument<256> document;
  document["device_id"] = DEVICE_ID;
  document["online"] = true;
  document["outputs"]["led"] = digitalRead(LED_PIN) == HIGH;
  char payload[256];
  serializeJson(document, payload);
  mqtt.publish(topic("state").c_str(), payload, true); // Retained current state.
}

void acknowledge(const char* requestId, const char* command, bool success) {
  StaticJsonDocument<192> document;
  document["device_id"] = DEVICE_ID;
  document["request_id"] = requestId;
  document["command"] = command;
  document["success"] = success;
  char payload[192];
  serializeJson(document, payload);
  mqtt.publish(topic("ack").c_str(), payload);
}

void onCommand(char*, byte* bytes, unsigned int length) {
  StaticJsonDocument<384> document;
  if (deserializeJson(document, bytes, length)) return;
  const char* command = document["command"] | "";
  const char* requestId = document["request_id"] | "";
  if (String(command) == "set_led" && document["value"].is<bool>()) {
    digitalWrite(LED_PIN, document["value"] ? HIGH : LOW);
    publishState();
    acknowledge(requestId, command, true);
  } else if (String(command) == "get_state") {
    publishState();
    acknowledge(requestId, command, true);
  } else {
    acknowledge(requestId, command, false); // Unknown commands are never executed.
  }
}

void ensureWifi() {
  if (WiFi.status() == WL_CONNECTED) return;
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
}

void ensureMqtt() {
  if (mqtt.connected() || millis() - lastMqttAttempt < 5000) return;
  lastMqttAttempt = millis();
  String status = topic("status");
  if (mqtt.connect(CLIENT_ID, status.c_str(), 1, true, "offline")) {
    mqtt.publish(status.c_str(), "online", true);
    mqtt.subscribe(topic("command").c_str());
    publishState();
  }
}

void setup() {
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  WiFi.mode(WIFI_STA);
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onCommand);
  ensureWifi();
}

void loop() {
  ensureWifi();
  ensureMqtt();
  mqtt.loop();
}
