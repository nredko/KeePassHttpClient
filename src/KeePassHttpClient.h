#pragma once

#ifdef _DEBUG
#define LOG(s) OutputDebugString((s).c_str());OutputDebugString(_T("\n"))
#else
#define LOG(s)
#endif

typedef std::basic_string<TCHAR> tstring;


class KeePassHttpClient
{
public:
	KeePassHttpClient(tstring Port, tstring Id, tstring Key);
	KeePassHttpClient(tstring Settings);
	tstring Settings();
	~KeePassHttpClient();
	Json::Value GetLogins(tstring Url, tstring SubmitUrl);
private:
#ifdef CURL_STATICLIB
	CURL *curl;
#endif
	tstring port = "";
	tstring id = "";
	tstring key = "";
	tstring iv = "";
	tstring hash = "";

	std::vector<uint8_t> Generate(size_t size);
	std::vector<uint8_t> Encrypt(std::vector<uint8_t> in);
	std::vector<uint8_t> Decrypt(std::vector<uint8_t> in, std::vector<uint8_t> rIv);
	tstring Encrypt(tstring in);
	tstring Decrypt(tstring in, tstring rIv);
	void Init();
	Json::Value Post(Json::Value data);

	void TestAssociate();
	void Associate();

};

