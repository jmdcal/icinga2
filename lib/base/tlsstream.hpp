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

#ifndef TLSSTREAM_H
#define TLSSTREAM_H

#include "base/i2-base.hpp"
#include "base/networkstream.hpp"
#include "base/tlsutility.hpp"
#include "base/fifo.hpp"

namespace icinga
{

/**
 * A TLS stream.
 *
 * @ingroup base
 */
class I2_BASE_API TlsStream : public Stream
{
public:
	DECLARE_PTR_TYPEDEFS(TlsStream);

	boost::signals2::signal<void(void)> OnDataAvailable;

	TlsStream(const NetworkStream::Ptr& stream, ConnectionRole role, const shared_ptr<SSL_CTX>& sslContext);

	shared_ptr<X509> GetClientCertificate(void) const;
	shared_ptr<X509> GetPeerCertificate(void) const;

	void Handshake(void);

	virtual void Close(void);

	virtual size_t Read(void *buffer, size_t count);
	virtual void Write(const void *buffer, size_t count);

	virtual bool IsEof(void) const;

	bool IsVerifyOK(void) const;

	size_t GetAvailableBytes(void) const;
	void MakeNonBlocking(void);

private:
	shared_ptr<SSL> m_SSL;
	mutable boost::condition_variable m_HandshakeCV;
	bool m_Eof;
	mutable boost::mutex m_SSLLock;
	bool m_HandshakeOK;
	bool m_VerifyOK;

	BIO *m_SendQ;
	BIO *m_RecvQ;

	mutable boost::mutex m_QueueLock;
	mutable boost::condition_variable m_QueueCV;
	FIFO::Ptr m_PlainSendQ;
	FIFO::Ptr m_PlainRecvQ;

	NetworkStream::Ptr m_Stream;
	ConnectionRole m_Role;

	bool m_Blocking;

	static int m_SSLIndex;
	static bool m_SSLIndexInitialized;

	void ProcessOutbound(void);
	void ProcessTls(void);

	static int ValidateCertificate(int preverify_ok, X509_STORE_CTX *ctx);
	static void NullCertificateDeleter(X509 *certificate);
};

}

#endif /* TLSSTREAM_H */
