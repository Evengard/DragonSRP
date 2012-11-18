/* This small application tests vectors listed
 * in RFC 5054 Appendix B
 * USE THIS APPLICATION ONLY FOR TESTING THE <RFC VECTORS>
 * ANY OTHER USE IS PURE NONSENSE AND VERY INSECURE
 * DUE TO PREDEFINED PRIVATE KEYS
 * WICH IN NORMAL ENVIRONMENT MUST BE ALWAYS RANDOM
 * 
 * Compilation:
 * in order to get this to work, debugging features must be
 * enabled using DSRP_DANGEROUS_TESTING preprocessor definition
 * in the dsrp library itself - needs complete recompilation
 * >> this is a safety feature
 * */

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#include "dsrp/srpserver.hpp"
#include "dsrp/srpclient.hpp"
#include "dsrp/srpverificator.hpp"
#include "dsrp/srpclientauthenticator.hpp"
#include "dsrp/user.hpp"
#include "dsrp/ng.hpp"

#include "dsrp/dsrpexception.hpp"
#include "dsrp/conversionexception.hpp"
#include "dsrp/usernotfoundexception.hpp"
#include "dsrp/conversion.hpp"

#include "dsrp/memorylookup.hpp"

#include "ossl/osslsha256.hpp"
#include "ossl/osslmathimpl.hpp"
#include "ossl/osslrandom.hpp"

using namespace DragonSRP;
using namespace DragonSRP::Ossl;
using namespace std;

// input values
const std::string rfc_username("alice");
const std::string rfc_password("password123");

int main(int argc, char **argv)
{	
	try {
		MemoryLookup lookup; // does not affect results
		OsslSha256 hash; // SHA1 is used in RFC5054
		
		// This is actually bypassed, but must be set (no effect)
		// Random generator is not used a and b values are set from RFC
		// Note: This is actually very dangerous in production environment
		//       use this FOR TESTING RFC VECTORS ONLY!!!!!!
		OsslRandom random; 
		
		// Load predefined N,g 1024bit RFC values
		Ng ng = Ng::predefined(1024);
		
		OsslMathImpl math(hash, ng);
		
		SrpServer srpserver(lookup, math, random);
		SrpClient srpclient(math, random);
		
		// Create user
		bytes username = Conversion::string2bytes(rfc_username);
		bytes password = Conversion::string2bytes(rfc_password);
		bytes salt = random.getRandom(8);
		
		// Calculate verificator
		bytes verificator = math.calculateVerificator(username, password, salt);
		

		
		cout << "INFO: calculated verificator= ";
		Conversion::printBytes(verificator);
		cout << endl;
		
		// Add user to server
		User u(username, verificator, salt);
		if (!lookup.userAdd(u))
		{
			cout << "Error: user already exists" << endl;
			cout << "!!! TEST VECTORS FAILURE !!!" << endl;
			return -1;
		}
		
		SrpClientAuthenticator sca = srpclient.getAuthenticator(username, password);
		
		
		cout << "INFO: calculated A= ";
		Conversion::printBytes(sca.getA());
		cout << endl;
		
		
		cout << "INFO: preliminary calculated B= ";
		Conversion::printBytes(srpserver.getB(username));
		cout << endl;
		
		SrpVerificator ver = srpserver.getVerificator(username, sca.getA());
		
		
		cout << "INFO: calculated B= ";
		Conversion::printBytes(ver.getB());
		cout << endl;
		
		// receive M1 from client
		bytes M1 = srpclient.getM1(salt, ver.getB(), sca);
		bytes M2;
		bytes server_K; // this is not premaster secret, this is already master secret
		ver.authenticate(M1, M2, server_K); // throws exception on bad password
	
		cout << "INFO: M1= ";
		Conversion::printBytes(M1);
		cout << endl << "INFO: M2= ";
		Conversion::printBytes(M2);
		cout << endl;
		
		bytes client_K = sca.getSessionKey(M2); // throws exception on bad password
		
		
		// display shared secret
		cout << "INFO: K(master session secret - server): ";
		Conversion::printBytes(server_K);
		cout << endl;
		
		// display shared secret
		cout << "INFO: K(master session secret - client): ";
		Conversion::printBytes(client_K);
		cout << endl;

		// if we get here, no exception was thrown
		// if auth fails DsrpException is thrown
		cout << "authentification successful" << endl;
		cout << "ALL TESTS PASSED OK SUCCESS" << endl;
		return 0;
	}
	catch (UserNotFoundException e)
	{
		cout << "UserNotFoundException: " << e.what() << endl;
		cout << "!!! TEST VECTORS FAILURE !!!" << endl;
	}
	catch (DsrpException e)
	{
		cout << "DsrpException: " << e.what() << endl;
		cout << "!!! TEST VECTORS FAILURE !!!" << endl;
	}
	catch (...)
	{
		cout << "unknown exception occured" << endl;
		cout << "!!! TEST VECTORS FAILURE !!!" << endl;
	}

	cout << "end!!! TEST VECTORS FAILURE !!!" << endl;
	return -1;
}
