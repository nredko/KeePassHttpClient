// NotesIPass.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "KeePassHttpClient.h"
#include "base64.h"

int _tmain(int argc, _TCHAR* argv[])
{

	KeePassHttpClient kee = KeePassHttpClient("http://localhost:19455", "", "");
	/*
* test if keepass is running, getting DB hash
	<< {"RequestType":"test-associate","TriggerUnlock":"False"}
	>> {"RequestType":"test-associate","Success":false,"Count":0,"Version":"1.8.4.0","Hash":"0"}
* test if key is associated (answer false)
	<< {"RequestType":"test-associate","TriggerUnlock":"False","Id":"id","Verifier":"==","Nonce":"=="}
	>> {"RequestType":"test-associate","Success":false,"Count":0,"Version":"1.8.4.0","Hash":"0"}
* associate key
	<< {"RequestType":"associate","Key":"=","Verifier":"==","Nonce":"="}
	>> {"RequestType":"associate","Success":true,"Id":"id","Count":0,"Version":"1.8.4.0","Hash":"0",
		"Nonce":"==","Verifier":"=="}
* test if key is associated (answer true)
	<< {"RequestType":"test-associate","TriggerUnlock":"False","Id":"Chrome","Verifier":"==","Nonce":"=="}
	>> {"RequestType":"test-associate","Success":true,"Id":"id","Count":0,"Version":"1.8.4.0","Hash":"0","Nonce":"==","Verifier":"=="}
* request logins
	<< {"RequestType":"get-logins","SortSelection":"true","TriggerUnlock":"false","Url":"==","SubmitUrl":"==","Id":"Chrome",
			"Verifier":"==","Nonce":"=="}
	>> {"RequestType":"get-logins","Success":true,"Id":"id","Count":1,"Version":"1.8.4.0","Hash":"0","Nonce":"==","Verifier":"=","
			Entries":[{"Login":"==","Password":"==","Uuid":"==","Name":"=="}]}

	*/
	//Json::Value data, res;
	//data["RequestType"] = "test-associate";
	//data["TriggerUnlock"] = "true";
	




	return 0;
}

