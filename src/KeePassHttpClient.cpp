#include "stdafx.h"
#include "KeePassHttpClient.h"
#include "base64.h"
#include "slowAes.h"

static bool curl_initialized = false;

void KeePassHttpClient::Init(){
	if (!curl_initialized)
		curl_global_init(CURL_GLOBAL_ALL);
	curl_initialized = true;
	if (key.empty())
		key = Base64::Encode(Generate(32));
	iv = Base64::Encode(Generate(16));
	TestAssociate();
}

KeePassHttpClient::KeePassHttpClient(tstring Url, tstring Id, tstring Key)
{
	url = Url;
	id = Id;
	key = Key;
	Init();
}

KeePassHttpClient::~KeePassHttpClient()
{
	curl_global_cleanup();
}

KeePassHttpClient::KeePassHttpClient(tstring Settings){
	std::vector<uint8_t>keyBytes = { 1, 23, 4, 1, 3, 46, 34, 2, 53, 3, 5, 76, 13, 14, 15, 16, 17, 18, 19, 20, 21, 2, 3, 124, 255, 16, 17, 21, 44, 3, 11, 111 };
	std::vector<uint8_t>ivBytes = { 1, 23, 4, 1, 3, 46, 34, 2, 53, 3, 5, 76, 13, 14, 15, 16 };
	std::vector<uint8_t> out;
	std::vector<uint8_t> in = Base64::Decode(Settings);
	out = decrypt(in, CBC, keyBytes, ivBytes);
	out.push_back(0);
	tstring s = tstring(reinterpret_cast<const TCHAR*>(out.data()));
	//LOG("dec settings: " + s);
	Json::Value ret;
	Json::Reader reader;

	bool parsingSuccessful = reader.parse(s, ret, false);
	if (!parsingSuccessful)
	{
		LOG("Failed to parse settings. " + reader.getFormattedErrorMessages());
		throw std::runtime_error("Failed to parse settings. " + reader.getFormattedErrorMessages());
	}
	url = ret["url"].asString();
	key = ret["key"].asString();
	id = ret["id"].asString();
	hash = ret["hash"].asString();
	Init();
}

tstring KeePassHttpClient::Settings(){
	Json::StreamWriterBuilder wbuilder;
	wbuilder["commentStyle"] = "None";
	wbuilder["indentation"] = Json::nullValue;
	Json::Value data;
	data["id"] = id;
	data["key"] = key;
	data["url"] = url;
	data["hash"] = hash;
	tstring settings = Json::writeString(wbuilder, data);
	//LOG("enc settings: " + settings);
	std::vector<uint8_t>keyBytes = { 1, 23, 4, 1, 3, 46, 34, 2, 53, 3, 5, 76, 13, 14, 15, 16, 17, 18, 19, 20, 21, 2, 3, 124, 255, 16, 17, 21, 44, 3, 11, 111 };
	std::vector<uint8_t>ivBytes = { 1, 23, 4, 1, 3, 46, 34, 2, 53, 3, 5, 76, 13, 14, 15, 16 };
	std::vector<uint8_t> out;
	std::vector<uint8_t> inBytes;
	inBytes.assign(settings.data(), settings.data() + (settings.size()*sizeof(TCHAR)));
	out = encrypt(inBytes, CBC, keyBytes, ivBytes);
	return Base64::Encode(out);
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
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

void KeePassHttpClient::TestAssociate(){
	Json::Value req;
	req["RequestType"] = "test-associate";
	req["TriggerUnlock"] = "true";
	if (!id.empty()){
		req["Id"] = id;
		req["Nonce"] = iv;
		req["Verifier"] = Encrypt(iv);
	}
	Json::Value ret = Post(req);
	if (ret["Success"].asBool())
		 hash = ret["Hash"].asString();
	else
		Associate();
}

void KeePassHttpClient::Associate()
{
	Json::Value req;
	req["RequestType"] = "associate";
	req["Key"] = key;
	req["Nonce"] = iv;
	req["Verifier"] = Encrypt(iv);
	Json::Value ret = Post(req);
	id = ret["Id"].asString();
	hash = ret["hash"].asString();
	LOG(Settings());
}

Json::Value KeePassHttpClient::GetLogins(tstring Url, tstring SubmitUrl){
	Json::Value req;
	req["RequestType"] = "get-logins";
	req["SortSelection"] = "true";
	req["Url"] = Encrypt(Url);
	req["SubmitUrl"] = Encrypt(SubmitUrl);
	req["Id"] = id;
	req["Nonce"] = iv;
	req["Verifier"] = Encrypt(iv);
	Json::Value ret = Post(req);
	for (size_t i = 0; i < ret["Entries"].size(); i++){
		ret["Entries"][i]["Name"] = Decrypt(ret["Entries"][i]["Name"].asString(), ret["Nonce"].asString());
		ret["Entries"][i]["Password"] = Decrypt(ret["Entries"][i]["Password"].asString(), ret["Nonce"].asString());
		ret["Entries"][i]["Uuid"] = Decrypt(ret["Entries"][i]["Uuid"].asString(), ret["Nonce"].asString());
		ret["Entries"][i]["Login"] = Decrypt(ret["Entries"][i]["Login"].asString(), ret["Nonce"].asString());
	}
	return ret["Entries"];
}

std::vector<uint8_t> KeePassHttpClient::Encrypt(std::vector<uint8_t> in){
	return encrypt(in, CBC, Base64::Decode(key), Base64::Decode(iv));
}

std::vector<uint8_t> KeePassHttpClient::Decrypt(std::vector<uint8_t> in, std::vector<uint8_t>ivBytes){
	return decrypt(in, CBC, Base64::Decode(key), ivBytes);
}


tstring KeePassHttpClient::Encrypt(tstring in){
	std::vector<uint8_t> inBytes;
	inBytes.assign(in.data(), in.data() + (in.size()*sizeof(TCHAR)));
	std::vector<uint8_t>  out = Encrypt(inBytes);
	return Base64::Encode(out);
}

tstring KeePassHttpClient::Decrypt(tstring in, tstring rIv){
	std::vector<uint8_t>  out = Decrypt(Base64::Decode(in), Base64::Decode(rIv));
	out.push_back(0);
	tstring outStr = tstring(reinterpret_cast<const TCHAR*>(out.data()));
	return outStr;
}
