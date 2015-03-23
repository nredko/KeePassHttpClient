#pragma once

#ifdef _DEBUG
#define LOG(s) OutputDebugString((s).c_str());OutputDebugString(_T("\n"))
#else
#define LOG(s)
#endif

typedef std::basic_string<TCHAR> tstring;


class KeePassHttpClient
{
private:
	CURL *curl;
	tstring url = "";
	tstring id = "";
	tstring key = "";
	tstring iv = "";

	std::vector<uint8_t> Generate(size_t size);
	std::vector<uint8_t> Encrypt(std::vector<uint8_t> in);
	std::vector<uint8_t> Decrypt(std::vector<uint8_t> in);
	std::vector<uint8_t> Encrypt1(std::vector<uint8_t> in);
	std::vector<uint8_t> Decrypt1(std::vector<uint8_t> in);
	Json::Value Post(Json::Value data);
	bool Associate();
public:
	KeePassHttpClient(tstring Url, tstring Id, tstring Key);
	~KeePassHttpClient();
	tstring GetKey();
	tstring GetId();
	tstring Encrypt(tstring in, bool base64 = true);
	tstring Decrypt(tstring in, bool base64 = true);
};

