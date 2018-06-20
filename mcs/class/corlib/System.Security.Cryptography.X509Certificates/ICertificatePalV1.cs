using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Internal.Cryptography
{
	internal interface ICertificatePalV1 : IDisposable
	{
		bool HasPrivateKey { get; }
		IntPtr Handle { get; }
		string Issuer { get; }
		string Subject { get; }
		byte[] Thumbprint { get; }
		string KeyAlgorithm { get; }
		byte[] KeyAlgorithmParameters { get; }
		byte[] PublicKeyValue { get; }
		byte[] SerialNumber { get; }
		string SignatureAlgorithm { get; }
		DateTime NotAfter { get; }
		DateTime NotBefore { get; }
		byte[] RawData { get; }
		int Version { get; }
	}
}
