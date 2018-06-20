using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
	internal interface IStorePalShim
	{
        IExportPal FromCertificate(ICertificatePalV1 cert);
	}
}
