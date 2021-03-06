
#include <time.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#include "dsrp/srpclient.hpp"
#include "dsrp/srpclientauthenticator.hpp"
#include "dsrp/srpserver.hpp"
#include "dsrp/srpverificator.hpp"
#include "dsrp/user.hpp"
#include "dsrp/ng.hpp"

#include "dsrp/dsrpexception.hpp"
#include "dsrp/conversionexception.hpp"
#include "dsrp/usernotfoundexception.hpp"
#include "dsrp/conversion.hpp"

#include "dsrp/memorylookup.hpp"

#include "ossl/osslsha1.hpp"
#include "ossl/osslmathimpl.hpp"
#include "ossl/osslrandom.hpp"

using namespace DragonSRP;
using namespace DragonSRP::Ossl;
using namespace std;

#define USERNAME "username"
#define PASSWORD "password"
#define SALTLEN 32
#define PRIMELEN 1024
#define ITERATIONS 1000

int main(int argc, char **argv)
{	
	clock_t start, finish;
	
	try {
		// -- benchmark initialization
		
		OsslSha1 hash;
		OsslRandom random;
		MemoryLookup lookup; // This stores users in memory (linked-list)
		
		Ng ng = Ng::predefined(PRIMELEN);
		OsslMathImpl math(hash, ng);
		
		SrpServer srpserver(lookup, math, random);
		SrpClient srpclient(math, random);
		
		bytes username = Conversion::string2bytes(USERNAME);
		bytes password = Conversion::string2bytes(PASSWORD);
		
		SrpClientAuthenticator sca = srpclient.getAuthenticator(username, password);
		
		// Create user
		bytes salt;
		if (salt.size() == 0) salt = random.getRandom(SALTLEN);
		bytes verificator = math.calculateVerificator(username, password, salt);
		
		User u(username, verificator, salt);
		
		if (!lookup.userAdd(u))
		{
			cout << "Error: user already exists" << endl;
			return -1;
		}
		// End of user creation
		
		start = clock();
		// ----- benchmark begin
		for (int i = 0; i < ITERATIONS; i++)
		{
			SrpVerificator ver = srpserver.getVerificator(username, sca.getA()); // C,A
			bytes M1 = srpclient.getM1(salt, ver.getB(), sca); // s, B		
			bytes M2, K_server;
			ver.authenticate(M1, M2, K_server); // M1	
			bytes K_client = sca.getSessionKey(M2); // M2
		}
		finish = clock();
		
		cout << "Time for sort (seconds): " << ((double)(finish - start))/CLOCKS_PER_SEC;
		cout << "end; ok" << endl;
		return 0;		
	}
	catch (UserNotFoundException e)
	{
		cout << "UserNotFoundException: " << e.what() << endl;
	}
	catch (DsrpException e)
	{
		cout << "DsrpException: " << e.what() << endl;
	}
	catch (...)
	{
		cout << "unknown exception occured" << endl;
	}
	return -1;
}

