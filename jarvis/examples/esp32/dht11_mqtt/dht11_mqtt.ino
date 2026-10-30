// ESP32 DHT11 telemetry example for JARVIS v0.9. Install DHT sensor library too.
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>

const char* WIFI_SSID = "YOUR_WIFI";
const char* WIFI_PASSWORD = "YOUR_PASSWORD";
const char* MQTT_HOST = "YOUR_BROKER";
const uint16_t MQTT_PORT = 1883;
const char* PREFIX = "jarvis/dev-001";
const char* DEVICE_ID = "esp32-dht11";
const char* CLIENT_ID = "esp32-dht11-unique";
const uint8_t DHT_PIN = 4;
const uint8_t DHT_TYPE = DHT11;

WiFiClient wifiClient;
PubSubClient mqtt(wifiClient);
DHT dht(DHT_PIN, DHT_TYPE);
unsigned long lastPublish = 0, lastMqttAttempt = 0;

String topic(const char* suffix) { return String(PREFIX) + "/devices/" + DEVICE_ID + "/" + suffix; }

void publishTelemetry() {
  float temperature = dht.readTemperature();
  float humidity = dht.readHumidity();
  if (isnan(temperature) || isnan(humidity)) return; // Invalid DHT readings are ignored.
  StaticJsonDocument<256> document;
  document["device_id"] = DEVICE_ID;
  document["sensors"]["temperature"] = temperature;
  document["sensors"]["humidity"] = humidity;
  document["units"]["temperature"] = "°C";
  document["units"]["humidity"] = "%";
  char payload[256];
  serializeJson(document, payload);
  mqtt.publish(topic("telemetry").c_str(), payload); // Telemetry is not retained.
}

void ensureConnections() {
  if (WiFi.status() != WL_CONNECTED) { WiFi.begin(WIFI_SSID, WIFI_PASSWORD); return; }
  if (mqtt.connected() || millis() - lastMqttAttempt < 5000) return;
  lastMqttAttempt = millis();
  String status = topic("status");
  if (mqtt.connect(CLIENT_ID, status.c_str(), 1, true, "offline")) mqtt.publish(status.c_str(), "online", true);
}

void setup() {
  WiFi.mode(WIFI_STA);
  dht.begin();
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
}

void loop() {
  ensureConnections();
  mqtt.loop();
  if (mqtt.connected() && millis() - lastPublish >= 5000) { lastPublish = millis(); publishTelemetry(); }
}
