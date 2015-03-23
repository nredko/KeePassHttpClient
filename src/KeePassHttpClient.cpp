#include "stdafx.h"
#include "KeePassHttpClient.h"
#include "base64.h"
#include "slowAes.h"

static bool curl_initialized = false;
KeePassHttpClient::KeePassHttpClient(tstring Url, tstring Id, tstring Key)
{
	url = Url;
	id = Id;
	key = Key;
	if (!curl_initialized)
		curl_global_init(CURL_GLOBAL_ALL);
	curl_initialized = true;
	if (key.empty())
		key = Base64::Encode(Generate(32));
	iv = Base64::Encode(Generate(16));
	if (id.empty())
		Associate();
}

KeePassHttpClient::~KeePassHttpClient()
{
	curl_global_cleanup();
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

std::string KeePassHttpClient::GetKey()
{
	return key;
}

std::string KeePassHttpClient::GetId()
{
	return id;
}
void ReplaceStringInPlace(tstring& subject, const tstring& search,	const tstring& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
}
Json::Value KeePassHttpClient::Post(Json::Value data){
	curl = curl_easy_init();
	assert(curl != NULL);
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	
	CURLcode res;
	tstring result;

	Json::StreamWriterBuilder wbuilder;
	wbuilder["commentStyle"] = "None";
	wbuilder["indentation"] = Json::nullValue;

	tstring req = Json::writeString(wbuilder, data);
	LOG(">> " + req);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req.c_str());

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK){
		tstring err = curl_easy_strerror(res);
		LOG("curl_easy_perform() failed: " + err);
		throw std::runtime_error(err);
	}
	LOG("<< " + result);
	
	if (curl != NULL)
		curl_easy_cleanup(curl);
	Json::Value ret;
	Json::Reader reader;

	bool parsingSuccessful = reader.parse(result, ret, false);

	if (!parsingSuccessful)
	{
		LOG("Failed to parse response. " + reader.getFormattedErrorMessages());
		throw std::runtime_error(reader.getFormattedErrorMessages());
	}

	Json::ValueType ret_type = ret.type();
	if (ret.type() == Json::ValueType::objectValue && ret.isMember("Error"))
	{
		LOG("Error: " + ret["Error"].asString());
		throw std::runtime_error(ret["Error"].asString());
	}
	return ret;
}
std::vector<uint8_t> KeePassHttpClient::Generate(size_t size){
	std::vector<uint8_t>bytes = std::vector<uint8_t>(size);
	for (size_t i = 0; i < size; i++)
		bytes[i] = rand() % 256;
	
	return bytes;
}

bool KeePassHttpClient::Associate()
{
	Json::Value req;
	req["RequestType"] = "test-associate";
	req["TriggerUnlock"] = "true";
	Json::Value ret = Post(req);
	Json::ValueType ret_type = ret.type();

	req.clear();
	req["RequestType"] = "associate";
	req["Key"] = key;
	req["Nonce"] = iv;
	req["Verifier"] = Encrypt(Base64::Encode(iv));
	ret = Post(req);
	id = ret["Id"].asString();
	return true;
}

std::vector<uint8_t> KeePassHttpClient::Encrypt(std::vector<uint8_t> in){
	std::vector<uint8_t>keyBytes = Base64::Decode(key);
	std::vector<uint8_t>ivBytes = Base64::Decode(iv);
	std::vector<uint8_t> out;
	out = encrypt(in, CBC, keyBytes, ivBytes);
	return out;
}

std::vector<uint8_t> KeePassHttpClient::Decrypt(std::vector<uint8_t> in){
	std::vector<uint8_t>keyBytes = Base64::Decode(key);
	std::vector<uint8_t>ivBytes = Base64::Decode(iv);
	std::vector<uint8_t> out;
	out = decrypt(in, CBC, keyBytes, ivBytes);
	return out;
}


tstring KeePassHttpClient::Encrypt(tstring in, bool base64){
	std::vector<uint8_t> inBytes;
	if (base64)
		inBytes = Base64::Decode(in);
	else
		inBytes.assign(in.data(), in.data() + (in.size()*sizeof(TCHAR)));
	std::vector<uint8_t>  out = Encrypt(inBytes);
	return Base64::Encode(out);
}
tstring KeePassHttpClient::Decrypt(tstring in, bool base64){
	std::vector<uint8_t> inBytes;
	if (base64)
		inBytes = Base64::Decode(in);
	else
		inBytes.assign(in.data(), in.data() + (in.size()*sizeof(TCHAR)));
	std::vector<uint8_t>  out = Decrypt(inBytes);
	out.push_back(0);
	return tstring(reinterpret_cast<const TCHAR*>(out.data()));
}
