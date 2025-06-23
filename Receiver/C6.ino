/*|--------------------------------------------------------------------------  -|*/
/*|Project: LoRa PPP with encrypted payload - ESP32-C6 + SX127X                 |*/
/*|Receiver: ESP32-C6 compatible with FSPI configuration                        |*/
/*|AES-CBC block cipher with hard-coded 256-bit AES key                         |*/
/*|AES key needs to be the same on sender side for encryption                   |*/
/*|Autor: Martin Chlebovec - Your-IoT (martinius96)                             |*/
/*|ESP32 receiver is using received IV in decryption process                    |*/
/*|Data are unpadded using PKCS#7 to the real struct size (24 B)                |*/
/*|Payload format: IV plaintext (16 bytes) + ciphertext (32 bytes), 48 in total |*/
/*|E-mail: martinius96@gmail.com                                                |*/
/*|-----------------------------------------------------------------------------|*/

#include <SPI.h>
#include <LoRa.h>
#include "mbedtls/aes.h"

#define LORA_SCK  19
#define LORA_MISO 20
#define LORA_MOSI 18

#define SS 21
#define RST 0
#define DI0 1
SPIClass spiLoRa(FSPI);

//Data structure
struct DataPacket {
  double a;
  double b;
  uint8_t c;
};

//AES key used for encryption and decryption
uint8_t key[32] = {
  0xa3, 0x7f, 0x19, 0x4d, 0x82, 0xe6, 0x3b, 0xc1,
  0x58, 0x92, 0x6a, 0x0e, 0xf3, 0xd4, 0xb7, 0x5c,
  0x1a, 0x8d, 0x33, 0x09, 0x7b, 0xee, 0x40, 0xda,
  0x26, 0x64, 0xbe, 0x11, 0x75, 0x90, 0xcb, 0x2f
};

// PKCS#7 unpadding
int pkcs7_unpad(uint8_t* input, int input_len) {
  if (input_len == 0) return 0;
  int pad_len = input[input_len - 1];
  if (pad_len <= 0 || pad_len > 16) return input_len;
  for (int i = input_len - pad_len; i < input_len; i++) {
    if (input[i] != pad_len) return input_len; // neplatný padding
  }
  return input_len - pad_len;
}

void printHex(const uint8_t* data, int len) {
  for (int i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  Serial.println("Init of LoRa Receiver...");
  spiLoRa.begin(LORA_SCK, LORA_MISO, LORA_MOSI, SS);
  LoRa.setSPI(spiLoRa);
  LoRa.setPins(SS, RST, DI0);

  if (!LoRa.begin(433800000)) {
    Serial.println("Error during initialization of LoRa!");
    while (true);
  }

  LoRa.setSpreadingFactor(8);
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(8);
  LoRa.setPreambleLength(8);
  LoRa.setSyncWord(0x15);
  LoRa.enableCrc();

  Serial.println("LoRa initialized Waiting for packets...");
  LoRa.receive();
}

void loop() {
  int packetSize = LoRa.parsePacket();
  if (packetSize > 0) {
    Serial.println("Packet received!");

    uint8_t buffer[80];
    int len = LoRa.readBytes(buffer, packetSize);

    if (len < 17) {
      Serial.println("Packet is too short!");
      return;
    }

    uint8_t iv[16];
    memcpy(iv, buffer, 16);
    uint8_t* encrypted = buffer + 16;
    int encrypted_len = len - 16;
    Serial.print("IV: ");
    printHex(iv, 16);
    Serial.print("Payload (encrypted): ");
    printHex(encrypted, encrypted_len);
    uint8_t decrypted[64];
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encrypted_len, iv_copy, encrypted, decrypted);
    mbedtls_aes_free(&aes);

    int unpadded_len = pkcs7_unpad(decrypted, encrypted_len);
    if (unpadded_len != sizeof(DataPacket)) {
      Serial.println("Size mismatch after unpadding");
      return;
    }

    DataPacket packet;
    memcpy(&packet, decrypted, sizeof(DataPacket));

    int rssi = LoRa.packetRssi();
    float snr = LoRa.packetSnr();
    long freqErr = LoRa.packetFrequencyError();

    Serial.printf("Received data - decrypted:\n");
    Serial.printf("a: %.6f\n", packet.a);
    Serial.printf("b: %.6f\n", packet.b);
    Serial.printf("c: %u\n", packet.c);
/*   
    Serial.printf("RSSI: %d dBm\n", rssi);
    Serial.printf("SNR: %.2f dB\n", snr);
    Serial.printf("Freq Error: %ld Hz\n\n", freqErr);
*/  
}
}
