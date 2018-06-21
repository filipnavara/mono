//
// Copyright (c) 2018 Microsoft
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
	/// <summary>
	/// Fully managed implementation of OidLookup for the commonly supported Oids.
	/// </summary>
	internal static partial class OidLookup
	{
		private static bool ShouldUseCache(OidGroup oidGroup)
		{
			return true;
		}

		private static string NativeOidToFriendlyName(string oid, OidGroup oidGroup, bool fallBackToAllGroups)
		{
			string friendlyName;
			if (s_extraOidToFriendlyName.TryGetValue (oid, out friendlyName)) {
				return friendlyName;
			}
			return null;
		}

		private static string NativeFriendlyNameToOid(string friendlyName, OidGroup oidGroup, bool fallBackToAllGroups)
		{
			string oid;
			if (s_extraFriendlyNameToOid.TryGetValue (friendlyName, out oid)) {
				return oid;
			}
			return null;
		}

		private static readonly Dictionary<string, string> s_extraFriendlyNameToOid =
			new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
				{ "pkcs7-data", "1.2.840.113549.1.7.1" },
				{ "contentType", "1.2.840.113549.1.9.3" },
				{ "messageDigest", "1.2.840.113549.1.9.4" },
				{ "signingTime", "1.2.840.113549.1.9.5" },
				{ "Subject Key Identifier", "2.5.29.14" },
				{ "Key Usage", "2.5.29.15" },
				{ "Subject Alternative Name", "2.5.29.17" },
				{ "Basic Constraints", "2.5.29.19" },
				{ "Extended Key Usage", "2.5.29.37" },
				{ "Netscape Cert Type", "2.16.840.1.113730.1.1" },
			};

		private static readonly Dictionary<string, string> s_extraOidToFriendlyName =
			s_extraFriendlyNameToOid.ToDictionary(kvp => kvp.Value, kvp => kvp.Key);
	}
}
