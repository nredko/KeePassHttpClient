// NotesIPass.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "KeePassHttpClient.h"
#include "base64.h"

int _tmain(int argc, _TCHAR* argv[])
{

	KeePassHttpClient kee = KeePassHttpClient("19455", "", "");
	LOG(kee.Settings());
	//KeePassHttpClient kee = KeePassHttpClient("aK/MltBZG3BK/Pl/kt0eWayfn8Kf7xWUb30/cvZgqRui/PdOpcWvI73bTbQCQLBi/y/HDbR7vNH56zgr/uSieqr9gpH/e6fBwb7Eq2IGclP8Bw6+OhHhFWuR9X0vi0dGH4aS8bvN4fc5OyS/lPVoXA==");
	
	//Json::Value entries = kee.GetLogins(tstring("http://build.inexika.com"), tstring("http://build.inexika.com"));
	Json::Value entries = kee.GetLogins(tstring("notes://Nikolay V Redko/NeoSoft"), tstring(""));
	LOG(entries.toStyledString());
	return 0;
}

