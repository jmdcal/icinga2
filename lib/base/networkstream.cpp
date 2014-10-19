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

#include "base/networkstream.hpp"
#include "base/objectlock.hpp"

using namespace icinga;

NetworkStream::NetworkStream(const Socket::Ptr& socket)
	: m_Socket(socket), m_Eof(false)
{
	m_SendQ = make_shared<FIFO>();
	m_RecvQ = make_shared<FIFO>();

	m_Socket->MakeNonBlocking();
	Poll::Register(m_Socket->GetFD(), this);
}

NetworkStream::~NetworkStream(void)
{
	Close();
}

void NetworkStream::Close(void)
{
	Poll::Unregister(m_Socket->GetFD());
	m_Socket->Close();
}

bool NetworkStream::WantRead(void) const
{
	return true;
}

bool NetworkStream::WantWrite(void) const
{
	ObjectLock olock(m_SendQ);
	return (m_SendQ->GetAvailableBytes() > 0);
}

void NetworkStream::ProcessReadable(void)
{
	char buffer[4096];
	size_t rc = m_Socket->Read(buffer, 4096);

	if (rc > 0) {
		{
			ObjectLock olock(m_RecvQ);
			m_RecvQ->Write(buffer, rc);
		}

		OnDataAvailable();
	} else {
		Close();
		m_Eof = true;
	}
}

void NetworkStream::ProcessWritable(void)
{
	ObjectLock olock(m_SendQ);
	size_t len = m_Socket->Write(m_SendQ->Peek(), m_SendQ->GetAvailableBytes());
	if (len > 0)
		m_SendQ->Read(NULL, len);
	else {
		Close();
		m_Eof = true;
	}
}

size_t NetworkStream::GetAvailableBytes(void) const
{
	ObjectLock olock(m_RecvQ);
	return m_RecvQ->GetAvailableBytes();
}

/**
 * Reads data from the stream.
 *
 * @param buffer The buffer where data should be stored. May be NULL if you're
 *		 not actually interested in the data.
 * @param count The number of bytes to read from the queue.
 * @returns The number of bytes actually read.
 */
size_t NetworkStream::Read(void *buffer, size_t count)
{
	ObjectLock olock(m_RecvQ);
	return m_RecvQ->Read(buffer, count);
}

/**
 * Writes data to the stream.
 *
 * @param buffer The data that is to be written.
 * @param count The number of bytes to write.
 * @returns The number of bytes written
 */
void NetworkStream::Write(const void *buffer, size_t count)
{
	ObjectLock olock(m_SendQ);
	m_SendQ->Write(buffer, count);
	Poll::Notify();
}

bool NetworkStream::IsEof(void) const
{
	ObjectLock olock(m_RecvQ);
	return m_RecvQ->GetAvailableBytes() == 0 && m_Eof;
}
