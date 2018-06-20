using System;
using System.Security.Cryptography.X509Certificates;

namespace Internal.Cryptography.Pal
{
	static class StorePal
	{
		public static IExportPal FromCertificate(ICertificatePalV1 cert)
		{
			throw new NotImplementedException();
			//return shim.FromCertificate (cert);
		}
	}
}
