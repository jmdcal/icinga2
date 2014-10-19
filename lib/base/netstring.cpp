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

#include "base/netstring.hpp"
#include "base/debug.hpp"
#include <sstream>

using namespace icinga;

/**
 * Reads data from a stream in netstring format.
 *
 * @param stream The stream to read from.
 * @param[out] str The String that has been read from the IOQueue.
 * @param context The NetString read context.
 * @returns true if a complete String was read from the IOQueue, false otherwise.
 * @exception invalid_argument The input stream is invalid.
 * @see https://github.com/PeterScott/netstring-c/blob/master/netstring.c
 */
bool NetString::ReadStringFromStream(const Stream::Ptr& stream, String *str, NetStringContext& context)
{
	while (context.HeaderLength == 0 || context.Header[context.HeaderLength - 1] != ':') {
		/* Read one byte. */
		int rc = stream->Read(context.Header + context.HeaderLength, 1);

		if (rc == 0)
			return false;

		ASSERT(rc == 1);

		context.HeaderLength++;

		if (context.HeaderLength == sizeof(context.Header))
			BOOST_THROW_EXCEPTION(std::invalid_argument("Invalid NetString (missing :)"));
	}

	/* no leading zeros allowed */
	if (context.Header[0] == '0' && isdigit(context.Header[1]))
		BOOST_THROW_EXCEPTION(std::invalid_argument("Invalid NetString (leading zero)"));

	size_t len, i;

	len = 0;
	for (i = 0; i < context.HeaderLength && isdigit(context.Header[i]); i++) {
		/* length specifier must have at most 9 characters */
		if (i >= 9)
			BOOST_THROW_EXCEPTION(std::invalid_argument("Length specifier must not exceed 9 characters"));

		len = len * 10 + (context.Header[i] - '0');
	}

	/* read the whole message */
	size_t data_length = len + 1;

	if (!context.Data)
		context.Data = new char[data_length];

	if (!context.Data)
		BOOST_THROW_EXCEPTION(std::bad_alloc());

	size_t rc = stream->Read(context.Data + context.DataLength, data_length - context.DataLength);
	
	context.DataLength += rc;

	if (context.DataLength < data_length)
		return false;

	if (context.Data[context.DataLength - 1] != ',')
		BOOST_THROW_EXCEPTION(std::invalid_argument("Invalid NetString (missing ,)"));
	
	*str = String(&context.Data[0], &context.Data[context.DataLength]);

	context = NetStringContext();

	return true;
}

/**
 * Writes data into a stream using the netstring format.
 *
 * @param stream The stream.
 * @param str The String that is to be written.
 */
void NetString::WriteStringToStream(const Stream::Ptr& stream, const String& str)
{
	std::ostringstream msgbuf;
	msgbuf << str.GetLength() << ":" << str << ",";

	String msg = msgbuf.str();
	stream->Write(msg.CStr(), msg.GetLength());
}
