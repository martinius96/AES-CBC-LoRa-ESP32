/*|--------------------------------------------------------------------------  -|*/
/*|Project: LoRa PPP with encrypted payload - ESP32 + SX127X                    |*/
/*|Sender: ESP32 compatible (ESP32-WROOM-32, ESP32-S)                           |*/
/*|AES-CBC block cipher with hard-coded 256-bit AES key                         |*/
/*|AES key needs to be the same on receiver side for descryption                |*/
/*|Sender: ESP32 compatible (ESP32-WROOM-32, ESP32-S)                           |*/
/*|Autor: Martin Chlebovec - Your-IoT (martinius96)                             |*/
/*|ESP32 using RNG to generate IV each time before transmission & also data     |*/
/*|Data are padded using PKCS#7 to 16 byte blocks                               |*/
/*|Payload format: IV plaintext (16 bytes) + ciphertext (32 bytes), 48 in total |*/
/*|E-mail: martinius96@gmail.com                                                |*/
/*|-----------------------------------------------------------------------------|*/

#include <SPI.h>
#include <LoRa.h>
#include <WiFi.h>
#include "mbedtls/aes.h"
#include "esp_system.h"
#define uS_TO_S_FACTOR 1000000
#define TIME_TO_SLEEP  5

#define SS 5
#define RST 14
#define DI0 2

RTC_DATA_ATTR unsigned long BootCount;

//Data structure
struct DataPacket {
  double a;     // 8 B
  double b;     // 8 B
  uint8_t c;    // 1 B
};



// PKCS#7 padding
int pkcs7_pad(uint8_t* input, int input_len, uint8_t* output, int block_size = 16) {
  int pad_len = block_size - (input_len % block_size);
  int total_len = input_len + pad_len;
  memcpy(output, input, input_len);
  for (int i = input_len; i < total_len; i++) {
    output[i] = pad_len;
  }
  return total_len;
}

//AES key used for encryption and decryption
uint8_t key[32] = {
  0xa3, 0x7f, 0x19, 0x4d, 0x82, 0xe6, 0x3b, 0xc1,
  0x58, 0x92, 0x6a, 0x0e, 0xf3, 0xd4, 0xb7, 0x5c,
  0x1a, 0x8d, 0x33, 0x09, 0x7b, 0xee, 0x40, 0xda,
  0x26, 0x64, 0xbe, 0x11, 0x75, 0x90, 0xcb, 0x2f
};

//IV generator with ESP32's RNG
void generateRandomIV(uint8_t* iv, int len) {
  for (int i = 0; i < len; i++) {
    iv[i] = esp_random() & 0xFF;
  }
}

void printHex(uint8_t* data, int len) {
  for (int i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}


bool initLoRa(unsigned long timeout_ms) {
  unsigned long start = millis();
  while (!LoRa.begin(433800000)) {
    if (millis() - start > timeout_ms) {
      Serial.println("LoRa initialization timed out");
      return false;
    }
    delay(100);
  }
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(500);

  WiFi.mode(WIFI_OFF);
  Serial.println("Init of LoRa Transmitter...");
  LoRa.setPins(SS, RST, DI0);

  if (!initLoRa(5000)) { // timeout 5 sekúnd
    Serial.println("Not able to init LoRa, going to sleep...");
    esp_sleep_enable_timer_wakeup(60 * uS_TO_S_FACTOR);
    esp_deep_sleep_start();
  }

  // Nastavenie LoRa parametrov
  LoRa.setTxPower(7);
  LoRa.setSpreadingFactor(8);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(8);
  LoRa.setPreambleLength(8);
  LoRa.setSyncWord(0x15);
  LoRa.enableCrc();

  Serial.println("LoRa initialized!");

  DataPacket packet;
  packet.a = ((double)(esp_random() % 9000000) / 100000.0) + 40.000000;
  packet.b = ((double)(esp_random() % 1000000) / 100000.0) + 10.000000;
  packet.c = esp_random() & 0xFF;

  uint8_t* input = (uint8_t*)&packet;
  int input_len = sizeof(DataPacket);

  uint8_t padded[64];
  int padded_len = pkcs7_pad(input, input_len, padded);

  uint8_t iv[16];
  generateRandomIV(iv, 16);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, key, 256);

  uint8_t encrypted[64];
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv_copy, padded, encrypted);


  uint8_t final_output[16 + 64];
  memcpy(final_output, iv, 16);
  memcpy(final_output + 16, encrypted, padded_len);

  Serial.print("IV (hex): ");
  printHex(iv, 16);

  Serial.print("Encrypted (hex): ");
  printHex(encrypted, padded_len);

  Serial.print("Final output (IV + Encrypted): ");
  printHex(final_output, padded_len + 16);

  Serial.println("Sending encrypted data (IV + ciphertext)...");

  LoRa.beginPacket();
  LoRa.write(final_output, padded_len + 16);
  int result = LoRa.endPacket();
  if (result == 1) {
    Serial.println("Data sent!");
  } else {
    Serial.println("Data werent sent!");
  }

  delay(250);
  LoRa.sleep();

  if (BootCount < 1) {
    delay(30000);
  }
  BootCount++;

  Serial.println("Setup ESP32 to sleep for every " + String(TIME_TO_SLEEP) + " seconds");
  esp_sleep_enable_timer_wakeup(TIME_TO_SLEEP * uS_TO_S_FACTOR);
  esp_deep_sleep_start();
}

void loop() {
}
