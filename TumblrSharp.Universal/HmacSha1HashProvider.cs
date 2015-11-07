using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace DontPanic.TumblrSharp
{
    /// <summary>
    ///     Provides an implementation of <see cref="IHmacSha1HashProvider" /> for signing OAuth requests.
    /// </summary>
    public class HmacSha1HashProvider : IHmacSha1HashProvider
    {
        /// <summary>
        ///     Gets a HMAC-SHA1 hash for an OAuth request.
        /// </summary>
        /// <param name="consumerSecret">
        ///     The consumer secret.
        /// </param>
        /// <param name="oauthSecret">
        ///     The OAuth secret.
        /// </param>
        /// <param name="signatureBaseString">
        ///     The signature base string for which to compute the hash.
        /// </param>
        /// <returns>
        ///     A HMAC-SHA1 hash of <paramref name="signatureBaseString" />.
        /// </returns>
        public string ComputeHash(string consumerSecret, string oauthSecret, string signatureBaseString)
        {
            if (signatureBaseString == null)
                return null;

            var secretKey = Encoding.UTF8.GetBytes(string.Format("{0}&{1}", consumerSecret, oauthSecret));
            var objMacProv = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
            var hash = objMacProv.CreateHash(secretKey.AsBuffer());
            hash.Append(CryptographicBuffer.ConvertStringToBinary(signatureBaseString, BinaryStringEncoding.Utf8));
            return CryptographicBuffer.EncodeToBase64String(hash.GetValueAndReset());
        }
    }
}