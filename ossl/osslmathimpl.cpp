/* ===============================================================  @
*  DragonSRP, C++ library implementing Secure Remote Protocol       *
*  Copyright (C) 2011 Pavel Slechta                                 *
*  <slechta@email.cz>                                               *
*                                                                   *
*  DragonSRP is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Lesser General Public       *
*  License as published by the Free Software Foundation; either     *
*  version 3 of the License, or (at your option) any later version. *
*                                                                   *
*  DragonSRP is distributed in the hope that it will be useful,     *
*  but WITHOUT ANY WARRANTY; without even the implied warranty of   *
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU *
*  Lesser General Public License for more details.                  *
*                                                                   *
*  You should have received a copy of the GNU Lesser General Public *
*  License along with DragonSRP.                                    *
*  If not, see <http://www.gnu.org/licenses/>.                      *
@  =============================================================== */

/* ===============================================================  @
*  In addition, as a special exception, the copyright holders give  *
*  permission to link the code of portions of this program with the *
*  OpenSSL library under certain conditions as described in each    *
*  individual source file, and distribute linked combinations       *
*  including the two.                                               *
*  You must obey the GNU Lesser General Public License in all       *
*  respects for all of the code used other than OpenSSL.            *
*  If you modify file(s) with this exception, you may extend        *
*  this exception to your version of the file(s), but you are not   *
*  obligated to do so.  If you do not wish to do so, delete this    *
*  exception statement from your version. If you delete this        *
*  exception statement from all source files in the program, then   *
*  also delete it here.                                             *
@  =============================================================== */

/* ===============================================================  @
*  This product includes software developed by the OpenSSL Project  *
*  for use in the OpenSSL Toolkit. (http://www.openssl.org/)        *
*                                                                   *
*  This product includes cryptographic software                     *
*  written by Eric Young (eay@cryptsoft.com)                        *
*                                                                   *
*  This product includes software                                   *
*  written by Tim Hudson (tjh@cryptsoft.com)                        *
@  =============================================================== */


#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "osslmathimpl.hpp"
#include "osslconversion.hpp"
#include "dsrp/conversion.hpp"

namespace DragonSRP
{
namespace Ossl
{
	
    OsslMathImpl::OsslMathImpl(HashInterface &hashInterface, Ng ngVal) :
		MathInterface(hashInterface, ngVal),
        N(BN_new()),
        g(BN_new()),
        k(BN_new()),
        ctx(BN_CTX_new())
    {
        // needs FIX: check primality of N and g generator???!!!!!!!!!!!!!
        
        bytes NN = ngVal.getN();
        bytes gg = ngVal.getg();
        
        OsslConversion::bytes2bignum(NN, N);
        OsslConversion::bytes2bignum(gg, g);
        
        bytes both = NN;
        
        both.push_back(0); // PAD(g); assuming len(g) < len(N)
        both.resize(2 * NN.size() - gg.size(), 0);
        
        both.insert(both.end(), gg.begin(), gg.end());
        bytes kk = hash.hash(both); // kk = H(N || PAD(g))
		
        OsslConversion::bytes2bignum(kk, k);        
	
		#ifdef DSRP_DANGEROUS_TESTING
			k_math = kk;
		#endif
			
    }
            
    OsslMathImpl::~OsslMathImpl()
    {
        BN_free(N);
        BN_free(g);
        BN_free(k);
        BN_CTX_free(ctx);
    }

    // A = g^a mod N
    bytes OsslMathImpl::calculateA(const bytes &aa)
    {		
		checkNg(); // will throw on error
        BIGNUM *a = BN_new();
        BIGNUM *A = BN_new();
        BIGNUM *tmp1 = BN_new();
                
        OsslConversion::bytes2bignum(aa, a);
        BN_mod_exp(A, g, a, N, ctx);
        
        bytes A_out;
        OsslConversion::bignum2bytes(A, A_out);
                
        BN_free(a);
        BN_free(A);
        BN_free(tmp1);
        
        return A_out;
    }

	bytes OsslMathImpl::calculateB(const bytes &verificator, const bytes &bb)
	{
		bytes B_out;

		BIGNUM *v = BN_new();
		BIGNUM *b = BN_new();
		BIGNUM *B = BN_new();
		BIGNUM *tmp1 = BN_new();
		BIGNUM *tmp2 = BN_new();
		OsslConversion::bytes2bignum(verificator, v);
		OsslConversion::bytes2bignum(bb, b);

		if (!BN_is_zero(v))
		{
			// Calculate B = k*v + g^b
			BN_mod_mul(tmp1, k, v, N, ctx);
			BN_mod_exp(tmp2, g, b, N, ctx);
			BN_mod_add(B, tmp1, tmp2, N, ctx);

			OsslConversion::bignum2bytes(B, B_out);

		}
		else
		{
			BN_free(v);
			BN_free(b);
			BN_free(B);
			BN_free(tmp1);
			BN_free(tmp2);

			throw DsrpException("Dsrp:B calculation failed:v is zero.");
		}

		BN_free(v);
		BN_free(b);
		BN_free(B);
		BN_free(tmp1);
		BN_free(tmp2);
		return B_out;
	}
            
    // u = H(A || B)
    // x = H(salt || H(username || ":" || password)
    // S = (B - k*(g^x)) ^ (a + ux)
    // K = H(S)
	void OsslMathImpl::clientChallenge(const bytes &salt, const bytes &aa, const bytes &AA, const bytes &BB, const bytes &username, const bytes &password, bytes &M1_out, bytes &M2_out, bytes &K_out)
	{   
		checkNg(); // will throw on error
		BIGNUM *B = BN_new();
		BIGNUM *x = BN_new();
		BIGNUM *a = BN_new();
		BIGNUM *u = BN_new();
		BIGNUM *tmp1 = BN_new();
		BIGNUM *tmp2 = BN_new();
		BIGNUM *tmp3 = BN_new();
		BIGNUM *S = BN_new();
		
		// Calculate u = H(PAD(A) || PAD(B))
		bytes cu;
		
		unsigned int len_N = BN_num_bytes(N);
		
		if (AA.size() < len_N) 
		{
			// PAD(A)
			cu.push_back(0);
			cu.resize(len_N - AA.size(), 0);
		}
		cu.insert(cu.begin(), AA.begin(), AA.end());
		
		if (BB.size() < len_N) 
		{
			// PAD(B)
			cu.push_back(0);
			cu.resize(len_N - BB.size(), 0);
		}
		cu.insert(cu.end(), BB.begin(), BB.end());
		
		bytes uu = hash.hash(cu);
		OsslConversion::bytes2bignum(uu, u);
		
		OsslConversion::bytes2bignum(BB, B);
		
		// Calculate x = HASH(salt || HASH(username || ":" || password)
		bytes ucp = username;
		ucp.push_back(58); // colon :
		Conversion::append(ucp, password);
		bytes hashUcp = hash.hash(ucp);
		Conversion::prepend(hashUcp, salt);
		bytes xx = hash.hash(hashUcp);
		OsslConversion::bytes2bignum(xx, x);
		
		#ifdef DSRP_DANGEROUS_TESTING
			x_client = xx;
		#endif
			
		//Calculate S
		// SRP-6a safety check
		if (!BN_is_zero(B) && !BN_is_zero(u))
		{
			OsslConversion::bytes2bignum(aa, a);
			BN_mod_mul(tmp1, u, x, N, ctx);    /* tmp1 = ux */
			BN_mod_add(tmp2, a, tmp1, N, ctx); /* tmp2 = a+ux  */
			BN_mod_exp(tmp1, g, x, N, ctx);    /* tmp1 = (g^x)%N */
			BN_mod_mul(tmp3, k, tmp1, N, ctx); /* tmp3 = k*((g^x)%N)       */
			BN_sub(tmp1, B, tmp3);             /* tmp1 = (B-k*((g^x)%N) */
			BN_mod_exp(S, tmp1, tmp2, N, ctx); /* S = ((B-k*((g^x)%N)^(a+ux)%N) */
			
			// Calculate K
			bytes SS;
			OsslConversion::bignum2bytes(S, SS);
			K_out = hash.hash(SS);
		
			// Calculate M1
			M1_out = calculateM1(username, salt, AA, BB, K_out);
			
			// Calculate M2 = H(A || M || K)
			bytes toHashM2 = AA;
			Conversion::append(toHashM2, M1_out);
			Conversion::append(toHashM2, K_out);
			M2_out = hash.hash(toHashM2);
			
			#ifdef DSRP_DANGEROUS_TESTING
				S_client_premaster_secret = SS;
			#endif
		}
		else
		{
			BN_free(B);
			BN_free(x);
			BN_free(a);
			BN_free(u);
			BN_free(tmp1);
			BN_free(tmp2);
			BN_free(tmp3);
			BN_free(S);
			
			throw DsrpException("Dsrp:Authentification failed:B or u is zero.");
		}
		
		BN_free(B);
		BN_free(x);
		BN_free(a);
		BN_free(u);
		BN_free(tmp1);
		BN_free(tmp2);
		BN_free(tmp3);
		BN_free(S);
			
	}
	
	void OsslMathImpl::serverChallenge(const bytes &username, const bytes &salt, const bytes &verificator, const bytes &AA, const bytes &bb, const bytes &BB, bytes &M1_out, bytes &M2_out, bytes &K_out)
	{
		checkNg(); // will throw on error
		
		bytes SS;
		
		BIGNUM *A = BN_new();
		BIGNUM *b = BN_new();
		BIGNUM *B = BN_new();
		BIGNUM *v = BN_new();
		BIGNUM *S = BN_new();
		BIGNUM *u = BN_new();
		BIGNUM *tmp1 = BN_new();
		BIGNUM *tmp2 = BN_new();

		OsslConversion::bytes2bignum(AA, A);
		OsslConversion::bytes2bignum(bb, b);
		OsslConversion::bytes2bignum(BB, B);
		OsslConversion::bytes2bignum(verificator, v);
		
		// there is neccessary to add the SRP6a security check
		// SRP-6a safety check
		
		BN_mod(tmp1, A, N, ctx);
		
		// I added the v != 0 check
		if (!BN_is_zero(tmp1) && !BN_is_zero(v))
		{

			// Calculate u = H(PAD(A) || PAD(B))
			bytes cu;
			
			unsigned int len_N = BN_num_bytes(N);
			
			if (AA.size() < len_N) 
			{
				// PAD(A)
				cu.push_back(0);
				cu.resize(len_N - AA.size(), 0);
			}
			Conversion::append(cu, AA);
			
			if (BB.size() < len_N) 
			{
				// PAD(B)
				cu.push_back(0);
				cu.resize(len_N - BB.size(), 0);
			}
			Conversion::append(cu, BB);
			
			bytes uu = hash.hash(cu);
			OsslConversion::bytes2bignum(uu, u);
		
			// Calculate S = (A *(v^u)) ^ b
			BN_mod_exp(tmp1, v, u, N, ctx);
			BN_mod_mul(tmp2, A, tmp1, N, ctx);
			BN_mod_exp(S, tmp2, b, N, ctx);
			OsslConversion::bignum2bytes(S, SS);
			K_out = hash.hash(SS);
			
			#ifdef DSRP_DANGEROUS_TESTING
				S_server_premaster_secret = SS;
				u_server = uu;
			#endif
			
			// Calculate M1 = H(H(N) XOR H(g) || H (s || A || B || K))
			M1_out = calculateM1(username, salt, AA, BB, K_out);
			
			// Calculate M2 = H(A || M || K)
			bytes toHashM2 = AA;
			Conversion::append(toHashM2, M1_out);
			Conversion::append(toHashM2, K_out);
			M2_out = hash.hash(toHashM2);		
		}
		else
		{
			BN_free(A);
			BN_free(b);
			BN_free(B);
			BN_free(v);
			BN_free(S);
			BN_free(u);
			BN_free(tmp1);
			BN_free(tmp2);
			
			throw DsrpException("Dsrp:Authentification failed:serverChalange: invalid parameters");
		}
		
		BN_free(A);
		BN_free(b);
		BN_free(B);
		BN_free(v);
		BN_free(S);
		BN_free(u);
		BN_free(tmp1);
		BN_free(tmp2);              
	}
	
	// M = H(H(N) XOR H(g) | H(username) | s | A | B | K)
	bytes OsslMathImpl::calculateM1(const bytes &username, const bytes &s, const bytes &A, const bytes &B, const bytes &K)
	{   
		bytes NN;
		bytes gg;
		
		OsslConversion::bignum2bytes(N, NN);
		OsslConversion::bignum2bytes(g, gg);
		
		bytes H_N = hash.hash(NN); 
		bytes H_g = hash.hash(gg);
		
		bytes H_username = hash.hash(username);
		bytes H_xor;
		
		H_xor.resize(hash.outputLen(), 0);
		for (unsigned int i = 0; i < hash.outputLen(); i++ ) H_xor[i] = H_N[i] ^ H_g[i];
	
		bytes toHash = H_xor;
		Conversion::append(toHash, H_username);
		Conversion::append(toHash, s);
		Conversion::append(toHash, A);
		Conversion::append(toHash, B);
		Conversion::append(toHash, K);		
		return hash.hash(toHash);
	}
	
	void OsslMathImpl::checkNg()
	{
		if (BN_is_zero(N)) throw DsrpException("OsslMathImpl: N was not set");
		if (BN_is_zero(g)) throw DsrpException("OsslMathImpl: g was not set");
		if (BN_is_zero(k)) throw DsrpException("OsslMathImpl: k was not set");
	}
 
	// throws
    bytes OsslMathImpl::calculateVerificator(const bytes &username, const bytes &password, const bytes &salt)
    {
		if (username.size() == 0 || password.size() == 0 || salt.size() == 0) throw DsrpException("Create verificator null parameter.");
		
		// Calculate x = HASH(salt || HASH(username || ":" || password)
		bytes ucp = username;
		ucp.push_back(58); // colon :
		Conversion::append(ucp, password);
		bytes hashUcp = hash.hash(ucp);
		Conversion::prepend(hashUcp, salt);
		bytes xx = hash.hash(hashUcp);
		
		// Calculate v = g ^ x;
		BIGNUM *x = BN_new();
		BIGNUM *v = BN_new();
		
		OsslConversion::bytes2bignum(xx, x);
		BN_mod_exp(v, g, x, N, ctx);
		
		bytes vv;
		OsslConversion::bignum2bytes(v, vv);
		BN_free(x);
		BN_free(v);
		
		#ifdef DSRP_DANGEROUS_TESTING
			x_vgen = xx;
		#endif
		
		return vv;
	}
 
// Namespace endings   
}
}
