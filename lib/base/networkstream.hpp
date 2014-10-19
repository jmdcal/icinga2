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

#ifndef NETWORKSTREAM_H
#define NETWORKSTREAM_H

#include "base/i2-base.hpp"
#include "base/stream.hpp"
#include "base/socket.hpp"
#include "base/fifo.hpp"
#include <boost/signals2.hpp>
#include "base/poll.hpp"

namespace icinga
{

/**
 * A network stream.
 *
 * @ingroup base
 */
class I2_BASE_API NetworkStream : public Stream, PollEventHandler
{
public:
	DECLARE_PTR_TYPEDEFS(NetworkStream);

	boost::signals2::signal<void(void)> OnDataAvailable;

	NetworkStream(const Socket::Ptr& socket);
	~NetworkStream(void);

	virtual size_t Read(void *buffer, size_t count);
	virtual void Write(const void *buffer, size_t count);

	virtual void Close(void);

	virtual bool IsEof(void) const;

	size_t GetAvailableBytes(void) const;

protected:
	virtual bool WantRead(void) const;
	virtual bool WantWrite(void) const;

	virtual void ProcessReadable(void);
	virtual void ProcessWritable(void);

private:
	Socket::Ptr m_Socket;
	bool m_Eof;
	FIFO::Ptr m_SendQ;
	FIFO::Ptr m_RecvQ;
};

}

#endif /* NETWORKSTREAM_H */
