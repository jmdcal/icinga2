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

#include "base/poll.hpp"
#include "base/debug.hpp"
#include "base/utility.hpp"
#include "base/logger.hpp"
#include "base/socket.hpp"
#include <boost/thread/thread.hpp>
#include <boost/thread/once.hpp>
#include <boost/foreach.hpp>

using namespace icinga;

static boost::once_flag l_PollOnceFlag = BOOST_ONCE_INIT;

static void StartPollThread(void);
static void PollThreadProc(void);

typedef std::map<SOCKET, PollEventHandler *> SocketMap;

static boost::mutex l_PollMutex;
static SocketMap l_Sockets;

static SOCKET l_NotifyFDs[2];

void Poll::Register(SOCKET fd, PollEventHandler *peh)
{
	boost::call_once(l_PollOnceFlag, &Poll::StartThread);

	{
		boost::mutex::scoped_lock lock(l_PollMutex);
		std::pair<SocketMap::iterator, bool> res = l_Sockets.insert(std::make_pair(fd, peh));
		ASSERT(res.second);
	}

	Notify();
}

void Poll::Unregister(SOCKET fd)
{
	{
		boost::mutex::scoped_lock lock(l_PollMutex);
		l_Sockets.erase(fd);
	}

	Notify();
}

/**
 * Notify the poll thread(s) that a file descriptor was added or removed.
 */
void Poll::Notify(void)
{
	if (send(l_NotifyFDs[1], "T", 1, 0) < 0 && errno != EINTR && errno != EAGAIN)
		Log(LogCritical, "base", "Write to event FD failed.");
}

void Poll::StartThread(void)
{
	SocketPair(l_NotifyFDs);

	Utility::SetNonBlockingSocket(l_NotifyFDs[0]);
	Utility::SetNonBlockingSocket(l_NotifyFDs[1]);

#ifndef _WIN32
	Utility::SetCloExec(l_NotifyFDs[0]);
	Utility::SetCloExec(l_NotifyFDs[1]);
#endif /* _WIN32 */

	boost::thread t(&Poll::IOThreadProc);
	t.detach();
}

void Poll::IOThreadProc(void)
{
	Utility::SetThreadName("PollIO");

	for (;;) {
		std::vector<struct pollfd> pfds;

		boost::mutex::scoped_lock lock(l_PollMutex);

		struct pollfd pfd;
		pfd.fd = l_NotifyFDs[0];
		pfd.events = POLLRDNORM;
		pfd.revents = 0;
		pfds.push_back(pfd);

		BOOST_FOREACH(const SocketMap::value_type& kv, l_Sockets) {
			struct pollfd pfd;
			pfd.fd = kv.first;
			pfd.events = 0;
			pfd.revents = 0;

			if (kv.second->WantRead())
				pfd.events |= POLLRDNORM;

			if (kv.second->WantWrite())
				pfd.events |= POLLWRNORM;

			pfds.push_back(pfd);
		}

		lock.unlock();
		poll(pfds.data(), pfds.size(), -1);
		lock.lock();

		BOOST_FOREACH(const struct pollfd& pfd, pfds) {
			if (pfd.fd == l_NotifyFDs[0] && pfd.revents & (POLLHUP|POLLRDNORM)) {
				char buffer[512];
				if (recv(l_NotifyFDs[0], buffer, sizeof(buffer), 0) < 0)
					Log(LogCritical, "base", "Read from event FD failed.");
			}

			SocketMap::const_iterator it = l_Sockets.find(pfd.fd);

			if (it == l_Sockets.end())
				continue;

			if (pfd.revents & (POLLNVAL))
				Log(LogWarning, "base", "Invalid FD in pollfd set.");

			if (pfd.revents & (POLLHUP|POLLRDNORM))
				it->second->ProcessReadable();

			if (pfd.revents & POLLWRNORM)
				it->second->ProcessWritable();
		}
	}
}
