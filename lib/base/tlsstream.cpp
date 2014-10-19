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

#include "base/tlsstream.hpp"
#include "base/utility.hpp"
#include "base/exception.hpp"
#include "base/logger.hpp"
#include "base/objectlock.hpp"
#include <boost/bind.hpp>
#include <iostream>

using namespace icinga;

int I2_EXPORT TlsStream::m_SSLIndex;
bool I2_EXPORT TlsStream::m_SSLIndexInitialized = false;

/**
 * Constructor for the TlsStream class.
 *
 * @param role The role of the client.
 * @param sslContext The SSL context for the client.
 */
TlsStream::TlsStream(const NetworkStream::Ptr& stream, ConnectionRole role, const shared_ptr<SSL_CTX>& sslContext)
	: m_Eof(false), m_VerifyOK(true), m_Stream(stream), m_Role(role), m_HandshakeOK(false), m_Blocking(true)
{
	std::ostringstream msgbuf;
	char errbuf[120];

	m_SSL = shared_ptr<SSL>(SSL_new(sslContext.get()), SSL_free);

	if (!m_SSL) {
		Log(LogCritical, "TlsStream")
		    << "SSL_new() failed with code " << ERR_peek_error() << ", \"" << ERR_error_string(ERR_peek_error(), errbuf) << "\"";

		BOOST_THROW_EXCEPTION(openssl_error()
			<< boost::errinfo_api_function("SSL_new")
			<< errinfo_openssl_error(ERR_peek_error()));
	}

	if (!m_SSLIndexInitialized) {
		m_SSLIndex = SSL_get_ex_new_index(0, const_cast<char *>("TlsStream"), NULL, NULL, NULL);
		m_SSLIndexInitialized = true;
	}

	SSL_set_ex_data(m_SSL.get(), m_SSLIndex, this);

	SSL_set_verify(m_SSL.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, &TlsStream::ValidateCertificate);

	m_SendQ = BIO_new(BIO_s_mem());

	m_RecvQ = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(m_RecvQ, -1);

	m_PlainSendQ = make_shared<FIFO>();
	m_PlainRecvQ = make_shared<FIFO>();

	m_Stream->OnDataAvailable.connect(boost::bind(&TlsStream::ProcessTls, this));

	SSL_set_bio(m_SSL.get(), m_RecvQ, m_SendQ);

	if (m_Role == RoleServer)
		SSL_set_accept_state(m_SSL.get());
	else
		SSL_set_connect_state(m_SSL.get());

	ProcessTls();
}

int TlsStream::ValidateCertificate(int preverify_ok, X509_STORE_CTX *ctx)
{
	SSL *ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
	TlsStream *stream = static_cast<TlsStream *>(SSL_get_ex_data(ssl, m_SSLIndex));
	if (!preverify_ok)
		stream->m_VerifyOK = false;
	return 1;
}

bool TlsStream::IsVerifyOK(void) const
{
	return m_VerifyOK;
}

/**
 * Retrieves the X509 certficate for this client.
 *
 * @returns The X509 certificate.
 */
shared_ptr<X509> TlsStream::GetClientCertificate(void) const
{
	boost::mutex::scoped_lock lock(m_SSLLock);
	return shared_ptr<X509>(SSL_get_certificate(m_SSL.get()), &Utility::NullDeleter);
}

/**
 * Retrieves the X509 certficate for the peer.
 *
 * @returns The X509 certificate.
 */
shared_ptr<X509> TlsStream::GetPeerCertificate(void) const
{
	boost::mutex::scoped_lock lock(m_SSLLock);
	return shared_ptr<X509>(SSL_get_peer_certificate(m_SSL.get()), X509_free);
}

/**
* Must be called with m_QueueLock held.
*/
void TlsStream::ProcessOutbound(void)
{
	char buffer[4096];
	int len;

	while (BIO_ctrl_pending(m_SendQ)) {
		len = BIO_read(m_SendQ, buffer, sizeof(buffer));

		if (len < 0)
			break;

		m_Stream->Write(buffer, len);
	}
}

void TlsStream::ProcessTls(void)
{
	std::ostringstream msgbuf;
	char errbuf[120];
	int rc, err;

	boost::mutex::scoped_lock qlock(m_QueueLock);

	size_t len;

	while ((len = m_Stream->GetAvailableBytes()) > 0) {
		char buffer[4096];

		if (len > sizeof(buffer))
			len = sizeof(buffer);

		len = m_Stream->Read(buffer, len);

		BIO_write(m_RecvQ, buffer, len);
	}

	if (!m_HandshakeOK) {
		{
			boost::mutex::scoped_lock lock(m_SSLLock);

			rc = SSL_do_handshake(m_SSL.get());

			if (rc <= 0)
				err = SSL_get_error(m_SSL.get(), rc);
			else {
				m_HandshakeOK = true;
				m_HandshakeCV.notify_all();
			}
		}

		ProcessOutbound();

		if (rc <= 0) {
			switch (err) {
				case SSL_ERROR_WANT_READ:
					break;
				case SSL_ERROR_WANT_WRITE:
					VERIFY(0);
					break;
				case SSL_ERROR_ZERO_RETURN:
					Close();
					break;
				default:
					if (ERR_peek_error() != 0)
						Log(LogCritical, "TlsStream")
						    << "SSL_do_handshake() failed with code " << ERR_peek_error() << ", \"" << ERR_error_string(ERR_peek_error(), errbuf) << "\"";

					BOOST_THROW_EXCEPTION(openssl_error()
						<< boost::errinfo_api_function("SSL_do_handshake")
						<< errinfo_openssl_error(ERR_peek_error()));
			}

			return;
		}
	}

	while (m_PlainSendQ->GetAvailableBytes()) {
		{
			boost::mutex::scoped_lock lock(m_SSLLock);
			rc = SSL_write(m_SSL.get(), m_PlainSendQ->Peek(), m_PlainSendQ->GetAvailableBytes());

			if (rc <= 0)
				err = SSL_get_error(m_SSL.get(), rc);
		}

		ProcessOutbound();

		if (rc <= 0) {
			switch (err) {
				case SSL_ERROR_WANT_READ:
					break;
				case SSL_ERROR_WANT_WRITE:
					VERIFY(0);
					break;
				case SSL_ERROR_ZERO_RETURN:
					Close();
					break;
				default:
					if (ERR_peek_error() != 0)
						Log(LogCritical, "TlsStream")
						    << "SSL_write() failed with code " << ERR_peek_error() << ", \"" << ERR_error_string(ERR_peek_error(), errbuf) << "\"";

					BOOST_THROW_EXCEPTION(openssl_error()
						<< boost::errinfo_api_function("SSL_write")
						<< errinfo_openssl_error(ERR_peek_error()));
			}

			return;
		}

		m_PlainSendQ->Read(NULL, rc);
	}

	for (;;) {
		char buffer[4096];

		{
			boost::mutex::scoped_lock lock(m_SSLLock);
			rc = SSL_read(m_SSL.get(), buffer, sizeof(buffer));

			if (rc <= 0)
				err = SSL_get_error(m_SSL.get(), rc);
		}

		ProcessOutbound();

		if (rc <= 0) {
			switch (err) {
				case SSL_ERROR_WANT_READ:
					break;
				case SSL_ERROR_WANT_WRITE:
					VERIFY(0);
					break;
				case SSL_ERROR_ZERO_RETURN:
					Close();
					break;
				default:
					if (ERR_peek_error() != 0)
						Log(LogCritical, "TlsStream")
						    << "SSL_read() failed with code " << ERR_peek_error() << ", \"" << ERR_error_string(ERR_peek_error(), errbuf) << "\"";

					BOOST_THROW_EXCEPTION(openssl_error()
						<< boost::errinfo_api_function("SSL_read")
						<< errinfo_openssl_error(ERR_peek_error()));
			}

			return;
		}

		m_PlainRecvQ->Write(buffer, rc);
		m_QueueCV.notify_all();

		qlock.unlock();
		OnDataAvailable();
		qlock.lock();
	}
}

void TlsStream::Handshake(void)
{
	boost::mutex::scoped_lock lock(m_SSLLock);

	while (!m_HandshakeOK)
		m_HandshakeCV.wait(lock);
}

/**
 * Processes data for the stream.
 */
size_t TlsStream::Read(void *buffer, size_t count)
{
	boost::mutex::scoped_lock lock(m_QueueLock);

	size_t available = m_PlainRecvQ->GetAvailableBytes();

	if (m_Eof && count > available)
		count = available;

	if (m_Blocking) {
		while (count > m_PlainRecvQ->GetAvailableBytes())
			m_QueueCV.wait(lock);
	}

	return m_PlainRecvQ->Read(buffer, count);
}

void TlsStream::Write(const void *buffer, size_t count)
{
	{
		boost::mutex::scoped_lock lock(m_QueueLock);
		m_PlainSendQ->Write(buffer, count);
	}

	ProcessTls();
}

/**
 * Closes the stream.
 */
void TlsStream::Close(void)
{
	m_Stream->Close();
}

bool TlsStream::IsEof(void) const
{
	boost::mutex::scoped_lock lock(m_QueueLock);
	return m_PlainRecvQ->GetAvailableBytes() == 0 && m_Stream->IsEof();
}

size_t TlsStream::GetAvailableBytes(void) const
{
	boost::mutex::scoped_lock lock(m_QueueLock);
	return m_PlainRecvQ->GetAvailableBytes();
}

void TlsStream::MakeNonBlocking(void)
{
	m_Blocking = false;
}
