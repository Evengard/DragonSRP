
#ifndef DSRP_OSSLMATHIMPL_HPP
#define DSRP_OSSLMATHIMPL_HPP

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "dsrp/common.hpp"
#include "dsrp/mathinterface.hpp"
#include "dsrp/ng.hpp"
#include "dsrp/conversion.hpp"

#include "dsrp/dsrpexception.hpp"

namespace DragonSRP
{
namespace Ossl
{
	
	class OsslMathImpl : public MathInterface
	{
		public:
			OsslMathImpl(HashInterface &hashInterface, Ng ngVal);
			~OsslMathImpl();
			bytes calculateA(const bytes &aa);
			void clientChallange(const bytes &salt, const bytes &aa, const bytes &AA, const bytes &BB, const bytes &username, const bytes &password, bytes &M1_out, bytes &M2_out, bytes &K_out);
			void serverChallange(const bytes &username, const bytes &salt, const bytes &verificator, const bytes &AA, const bytes &bb, bytes &B_out, bytes &M1_out, bytes &M2_out, bytes &K_out);
		private:
			bytes calculateM1(const bytes &username, const bytes &s, const bytes &A, const bytes &B, const bytes &K);
			void checkNg();
			
			BIGNUM *N;
			BIGNUM *g;
			BIGNUM *k;
			BN_CTX *ctx;
	};
	
// Namespace endings
}
}

#endif
