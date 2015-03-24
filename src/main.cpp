// NotesIPass.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "KeePassHttpClient.h"
#include "base64.h"

int _tmain(int argc, _TCHAR* argv[])
{

	//KeePassHttpClient kee = KeePassHttpClient("http://localhost:19455", "", "");
	//LOG(kee.Settings());
	KeePassHttpClient kee = KeePassHttpClient("aK/MltBZG3BK/Pl/kt0eWayfn8Kf7xWUb30/cvZgqRui/PdOpcWvI73bTbQCQLBi/y/HDbR7vNH56zgr/uSieqr9gpH/e6fBwb7Eq2IGclP8Bw6+OhHhFWuR9X0vi0dGH4aS8bvN4fc5OyS/lPVoXA==");
	
	Json::Value entries = kee.GetLogins(tstring("http://build.inexika.com"), tstring("http://build.inexika.com"));
	LOG(entries.toStyledString());
	//entries = kee.GetLogins(tstring("notes://Nikolay V Redko"), tstring(""));
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

