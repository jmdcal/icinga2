/******************************************************************************
* Icinga 2                                                                   *
* Copyright (C) 2012-2014 Icinga Development Team (http://www.icinga.org)    *
*                                                                            *
* This program is free software; you can redistribute it and/or              *
* modify it under the terms of the GNU General Public License                *
* as published by the Free Software Foundation; either version 2             *
* of the License, or (at your option) any later version.                     *
*                                                                            *
* This program is distributed in the hope that it will be useful,            *
* but WITHOUT ANY WARRANTY; without even the implied warranty of             *
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
* GNU General Public License for more details.                               *
*                                                                            *
* You should have received a copy of the GNU General Public License          *
* along with this program; if not, write to the Free Software Foundation     *
* Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.             *
******************************************************************************/

#ifndef POLL_H
#define POLL_H

#include "base/i2-base.hpp"
#include <boost/thread/mutex.hpp>
#include <map>

namespace icinga
{

class PollEventHandler
{
public:
	virtual bool WantRead(void) const = 0;
	virtual bool WantWrite(void) const = 0;

	virtual void ProcessReadable(void) = 0;
	virtual void ProcessWritable(void) = 0;
};

class I2_BASE_API Poll
{
public:
	static void Register(SOCKET fd, PollEventHandler *ppe);
	static void Unregister(SOCKET fd);
	static void Notify(void);

private:
	static void StartThread(void);
	static void IOThreadProc(void);

#ifdef _WIN32
	static void CALLBACK NotifyThreadAPC(ULONG_PTR dwParam);
#endif /* _WIN32 */
};

}

#endif /* POLL_H */