// ESP32 LDR + LED example. JARVIS accepts only set_led/get_state commands.
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>

const char* WIFI_SSID = "YOUR_WIFI";
const char* WIFI_PASSWORD = "YOUR_PASSWORD";
const char* MQTT_HOST = "YOUR_BROKER";
const uint16_t MQTT_PORT = 1883;
const char* PREFIX = "jarvis/dev-001";
const char* DEVICE_ID = "esp32-ldr-led";
const char* CLIENT_ID = "esp32-ldr-led-unique";
const int LDR_PIN = 34;
const int LED_PIN = 2;

WiFiClient wifiClient;
PubSubClient mqtt(wifiClient);
unsigned long lastPublish = 0, lastMqttAttempt = 0;
String topic(const char* suffix) { return String(PREFIX) + "/devices/" + DEVICE_ID + "/" + suffix; }

void stateAndAck(const char* requestId = "", const char* command = "", bool success = true) {
  StaticJsonDocument<256> state;
  state["device_id"] = DEVICE_ID; state["online"] = true;
  state["outputs"]["led"] = digitalRead(LED_PIN) == HIGH;
  char payload[256]; serializeJson(state, payload); mqtt.publish(topic("state").c_str(), payload, true);
  if (String(requestId).length()) {
    StaticJsonDocument<192> ack;
    ack["device_id"] = DEVICE_ID; ack["request_id"] = requestId; ack["command"] = command; ack["success"] = success;
    serializeJson(ack, payload); mqtt.publish(topic("ack").c_str(), payload);
  }
}

void callback(char*, byte* bytes, unsigned int length) {
  StaticJsonDocument<256> command;
  if (deserializeJson(command, bytes, length)) return;
  const char* name = command["command"] | ""; const char* request = command["request_id"] | "";
  if (String(name) == "set_led" && command["value"].is<bool>()) {
    digitalWrite(LED_PIN, command["value"] ? HIGH : LOW); stateAndAck(request, name, true);
  } else if (String(name) == "get_state") stateAndAck(request, name, true);
  else stateAndAck(request, name, false);
}

void connectMqtt() {
  if (WiFi.status() != WL_CONNECTED) { WiFi.begin(WIFI_SSID, WIFI_PASSWORD); return; }
  if (mqtt.connected() || millis() - lastMqttAttempt < 5000) return;
  lastMqttAttempt = millis(); String status = topic("status");
  if (mqtt.connect(CLIENT_ID, status.c_str(), 1, true, "offline")) {
    mqtt.publish(status.c_str(), "online", true); mqtt.subscribe(topic("command").c_str()); stateAndAck();
  }
}

void setup() {
  pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, LOW); WiFi.mode(WIFI_STA);
  mqtt.setServer(MQTT_HOST, MQTT_PORT); mqtt.setCallback(callback); WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
}

void loop() {
  connectMqtt(); mqtt.loop();
  if (mqtt.connected() && millis() - lastPublish >= 3000) {
    lastPublish = millis(); StaticJsonDocument<192> telemetry;
    telemetry["device_id"] = DEVICE_ID; telemetry["sensors"]["ldr"] = analogRead(LDR_PIN);
    char payload[192]; serializeJson(telemetry, payload); mqtt.publish(topic("telemetry").c_str(), payload);
  }
}
