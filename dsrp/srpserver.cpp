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

#include "srpserver.hpp"

namespace DragonSRP
{
	
	SrpServer::SrpServer(LookupInterface &lookupInterface, MathInterface &mathInterface, RandomInterface &randomInterface) :
		lookup(lookupInterface),
		math(mathInterface),
		random(randomInterface)
	{
			
	}	
	
	bytes SrpServer::getB(const bytes &username)
	{
		if (bb.size() == 0 || BB.size() == 0)
		{
			User usr = lookup.getByName(username); // throws if not found
			bb = random.getRandom(32); // length of salt, needs to be parametrized!
			BB = math.calculateB(usr.getVerificator(), bb);
		}
		return BB;
	}

	SrpVerificator SrpServer::getVerificator(const bytes &username, const bytes &AA)
	{
		// check status of authentification
		User usr = lookup.getByName(username); // throws if not found
		bytes M1, M2, K;
		if (bb.size() == 0 || BB.size() == 0)
		{
			getB(username);
		}
		math.serverChallenge(username, usr.getSalt(), usr.getVerificator(), AA, bb, BB, M1, M2, K); // throws on error
		return SrpVerificator(username, usr.getSalt(), BB, M1, M2, K);
	}
			
	#ifdef DSRP_DANGEROUS_TESTING
	    // injects custom b; used for testing rfc vectors
		SrpVerificator SrpServer::getVerificator(const bytes &username, const bytes &AA, const bytes &b)
		{
			// check status of authentification
			User usr = lookup.getByName(username); // throws if not found
			bytes M1, M2, K;

			bb = b;
			BB = math.calculateB(usr.getVerificator(), bb);
			
			math.serverChallenge(username, usr.getSalt(), usr.getVerificator(), AA, b, BB, M1, M2, K); // throws on error
			return SrpVerificator(username, usr.getSalt(), BB, M1, M2, K);
		}
	#endif
	
}
