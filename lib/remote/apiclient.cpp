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

#include "remote/apiclient.hpp"
#include "remote/apilistener.hpp"
#include "remote/apifunction.hpp"
#include "remote/jsonrpc.hpp"
#include "base/dynamictype.hpp"
#include "base/objectlock.hpp"
#include "base/utility.hpp"
#include "base/logger.hpp"
#include "base/exception.hpp"

using namespace icinga;

static Value SetLogPositionHandler(const MessageOrigin& origin, const Dictionary::Ptr& params);
REGISTER_APIFUNCTION(SetLogPosition, log, &SetLogPositionHandler);
static Value RequestCertificateHandler(const MessageOrigin& origin, const Dictionary::Ptr& params);
REGISTER_APIFUNCTION(RequestCertificate, pki, &RequestCertificateHandler);

ApiClient::ApiClient(const String& identity, bool authenticated, const TlsStream::Ptr& stream, ConnectionRole role)
	: m_Identity(identity), m_Authenticated(authenticated), m_Stream(stream), m_Role(role), m_Seen(Utility::GetTime())
{
	if (authenticated)
		m_Endpoint = Endpoint::GetByName(identity);

	m_Stream->OnDataAvailable.connect(boost::bind(&ApiClient::ProcessMessage, this));

	ProcessMessage();
}

String ApiClient::GetIdentity(void) const
{
	return m_Identity;
}

bool ApiClient::IsAuthenticated(void) const
{
	return m_Authenticated;
}

Endpoint::Ptr ApiClient::GetEndpoint(void) const
{
	return m_Endpoint;
}

TlsStream::Ptr ApiClient::GetStream(void) const
{
	return m_Stream;
}

ConnectionRole ApiClient::GetRole(void) const
{
	return m_Role;
}

void ApiClient::SendMessage(const Dictionary::Ptr& message)
{
	if (m_WriteQueue.GetLength() > 20000) {
		Log(LogWarning, "remote")
		    << "Closing connection for API identity '" << m_Identity << "': Too many queued messages.";
		Disconnect();
		return;
	}

	m_WriteQueue.Enqueue(boost::bind(&ApiClient::SendMessageSync, static_cast<ApiClient::Ptr>(GetSelf()), message));
}

void ApiClient::SendMessageSync(const Dictionary::Ptr& message)
{
	try {
		ObjectLock olock(m_Stream);
		if (m_Stream->IsEof())
			return;
		JsonRpc::SendMessage(m_Stream, message);
		if (message->Get("method") != "log::SetLogPosition")
			m_Seen = Utility::GetTime();
	} catch (const std::exception& ex) {
		std::ostringstream info;
		info << "Error while sending JSON-RPC message for identity '" << m_Identity << "'";
		Log(LogWarning, "ApiClient")
		    << info.str();
		Log(LogDebug, "ApiClient")
		    << info.str() << "\n" << DiagnosticInformation(ex);

		Disconnect();
	}
}

void ApiClient::Disconnect(void)
{
	Utility::QueueAsyncCallback(boost::bind(&ApiClient::DisconnectSync, static_cast<ApiClient::Ptr>(GetSelf())));
}

void ApiClient::DisconnectSync(void)
{
	Log(LogWarning, "ApiClient")
	    << "API client disconnected for identity '" << m_Identity << "'";

	if (m_Endpoint)
		m_Endpoint->RemoveClient(GetSelf());
	else {
		ApiListener::Ptr listener = ApiListener::GetInstance();
		listener->RemoveAnonymousClient(GetSelf());
	}

	m_Stream->Close();
}

bool ApiClient::ProcessMessage(void)
{
	Dictionary::Ptr message;

	if (m_Stream->IsEof()) {
		Disconnect();
		return false;
	}

	try {
		message = JsonRpc::ReadMessage(m_Stream, m_NSContext);
	} catch (const openssl_error& ex) {
		const unsigned long *pe = boost::get_error_info<errinfo_openssl_error>(ex);

		if (pe && *pe == 0)
			return false; /* Connection was closed cleanly */

		throw;
	}

	if (!message)
		return false;

	if (message->Get("method") != "log::SetLogPosition")
		m_Seen = Utility::GetTime();

	if (m_Endpoint && message->Contains("ts")) {
		double ts = message->Get("ts");

		/* ignore old messages */
		if (ts < m_Endpoint->GetRemoteLogPosition())
			return true;

		m_Endpoint->SetRemoteLogPosition(ts);
	}

	MessageOrigin origin;
	origin.FromClient = GetSelf();

	if (m_Endpoint) {
		if (m_Endpoint->GetZone() != Zone::GetLocalZone())
			origin.FromZone = m_Endpoint->GetZone();
		else
			origin.FromZone = Zone::GetByName(message->Get("originZone"));
	}

	String method = message->Get("method");

	Log(LogNotice, "ApiClient")
	    << "Received '" << method << "' message from '" << m_Identity << "'";

	Dictionary::Ptr resultMessage = make_shared<Dictionary>();

	try {
		ApiFunction::Ptr afunc = ApiFunction::GetByName(method);

		if (!afunc)
			BOOST_THROW_EXCEPTION(std::invalid_argument("Function '" + method + "' does not exist."));

		resultMessage->Set("result", afunc->Invoke(origin, message->Get("params")));
	} catch (const std::exception& ex) {
		resultMessage->Set("error", DiagnosticInformation(ex));
	}

	if (message->Contains("id")) {
		resultMessage->Set("jsonrpc", "2.0");
		resultMessage->Set("id", message->Get("id"));
		JsonRpc::SendMessage(m_Stream, resultMessage);
	}

	return true;
}

Value SetLogPositionHandler(const MessageOrigin& origin, const Dictionary::Ptr& params)
{
	if (!params)
		return Empty;

	double log_position = params->Get("log_position");
	Endpoint::Ptr endpoint = origin.FromClient->GetEndpoint();

	if (!endpoint)
		return Empty;

	if (log_position > endpoint->GetLocalLogPosition())
		endpoint->SetLocalLogPosition(log_position);

	return Empty;
}

Value RequestCertificateHandler(const MessageOrigin& origin, const Dictionary::Ptr& params)
{
	if (!params)
		return Empty;

	ApiListener::Ptr listener = ApiListener::GetInstance();
	String salt = listener->GetTicketSalt();

	Dictionary::Ptr result = make_shared<Dictionary>();

	if (salt.IsEmpty()) {
		result->Set("error", "Ticket salt is not configured.");
		return result;
	}

	String ticket = params->Get("ticket");
	String realTicket = PBKDF2_SHA1(origin.FromClient->GetIdentity(), salt, 50000);

	if (ticket != realTicket) {
		result->Set("error", "Invalid ticket.");
		return result;
	}

	shared_ptr<X509> cert = origin.FromClient->GetStream()->GetPeerCertificate();

	EVP_PKEY *pubkey = X509_get_pubkey(cert.get());
	X509_NAME *subject = X509_get_subject_name(cert.get());

	shared_ptr<X509> newcert = CreateCertIcingaCA(pubkey, subject);
	result->Set("cert", CertificateToString(newcert));

	String cacertfile = GetIcingaCADir() + "/ca.crt";
	shared_ptr<X509> cacert = GetX509Certificate(cacertfile);
	result->Set("ca", CertificateToString(cacert));

	return result;
}
