using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;
using Microsoft.Win32.SafeHandles;
using MX = Mono.Security.X509;

namespace Internal.Cryptography
{
	class CertificatePal : ICertificatePalV1
	{
		MX.X509Certificate x509;

		public CertificatePal (MX.X509Certificate x509)
		{
			this.x509 = x509;
		}

		public void Dispose ()
		{
		}

		public bool HasPrivateKey => false;
		public IntPtr Handle => IntPtr.Zero;
		public string Issuer => MX.X501.ToString (x509.GetIssuerName (), true, ", ", true);
		public string Subject => MX.X501.ToString (x509.GetSubjectName (), true, ", ", true);
		public string KeyAlgorithm => x509.KeyAlgorithm;
		public byte[] PublicKeyValue => x509.PublicKey;
		public byte[] SerialNumber => x509.SerialNumber;
		public string SignatureAlgorithm => x509.SignatureAlgorithm;
		public DateTime NotAfter => x509.ValidUntil.ToLocalTime();
		public DateTime NotBefore => x509.ValidFrom.ToLocalTime();
		public byte[] RawData => x509.RawData;
		public int Version => x509.Version;

		public byte[] KeyAlgorithmParameters {
			get {
				if (x509.KeyAlgorithmParameters == null)
					throw new CryptographicException (Locale.GetText ("Parameters not part of the certificate"));
				return x509.KeyAlgorithmParameters;
			}
		}

		public byte[] Thumbprint {
			get {
				SHA1 sha = SHA1.Create ();
				return sha.ComputeHash (x509.RawData);
			}
		}

		public static ICertificatePalV1 FromBlob(byte[] rawData, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
		{
			return new CertificatePal (new MX.X509Certificate (rawData));
		}

		public static ICertificatePalV1 FromHandle(IntPtr handle)
		{
			if (handle == IntPtr.Zero)
				throw new ArgumentException ("Invalid handle.");
			throw new NotSupportedException ();
		}

		public static ICertificatePalV1 FromOtherCert(X509Certificate cert)
		{
			if (cert.Pal is CertificatePal monoPal)
				return new CertificatePal (monoPal.x509);

			return new CertificatePal (new MX.X509Certificate (cert.GetRawCertData ()));
		}

		public static ICertificatePalV1 FromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
		{
			return FromBlob (File.ReadAllBytes (fileName), password, keyStorageFlags);
		}
	}
}
