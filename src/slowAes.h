enum keySize{
	SIZE_16 = 16,
	SIZE_24 = 24,
	SIZE_32 = 32
};

typedef enum modeOfOperation {
	OFB = 0,
	CFB = 1,
	CBC = 2
} AesMode;

std::vector<uint8_t> encrypt(std::vector<uint8_t> bytesIn,  AesMode mode, std::vector<uint8_t> key, std::vector<uint8_t> iv);
std::vector<uint8_t> decrypt(std::vector<uint8_t> cipherIn, AesMode mode, std::vector<uint8_t> key, std::vector<uint8_t> iv);