using System;
using System.IO;
using System.Security.Cryptography;

namespace Encryptide
{
    public static class CryptographyExtensions
    {
        #region Aes
        /// <summary>
        /// Encrypts bytes using AES.
        /// </summary>
        /// <param name="aes">AES key used to encrypt data.</param>
        /// <param name="data">Data to be encrypted.</param>
        /// <returns></returns>
        public static byte[] Encrypt(this Aes aes, byte[] data)
        {
            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                return PerformCryptography(data, encryptor);
            }
        }

        /// <summary>
        /// Decrypts bytes using AES.
        /// </summary>
        /// <param name="aes">AES key used to decrypt data.</param>
        /// <param name="data">Data to be decrypted.</param>
        /// <returns></returns>
        public static byte[] Decrypt(this Aes aes, byte[] data)
        {
            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                byte[] result = PerformCryptography(data, decryptor);
                return result;
            }
        }

        /// <summary>
        /// Encrypts or decrypts data.
        /// </summary>
        /// <param name="data">Data to be encrypted/decrypted.</param>
        /// <param name="cryptoTransform">The cryptography transform.</param>
        /// <returns></returns>
        private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }
        #endregion

        #region Rsa
        /// <summary>
        /// Decrypts data using RSA key.
        /// Inspired by: https://www.c-sharpcorner.com/UploadFile/75a48f/rsa-algorithm-with-C-Sharp2/
        /// </summary>
        /// <param name="rsa">RSA public/private key pair.</param>
        /// <param name="data">Data to be decrypted.</param>
        /// <returns>Decrypted byte array.</returns>
        public static byte[] Decrypt(this RSA rsa, byte[] data)
        {
            try
            {
                byte[] decryptedData;
                using (RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider())
                {
                    rsaCryptoServiceProvider.ImportParameters(rsa.ExportParameters(true));
                    decryptedData = rsaCryptoServiceProvider.Decrypt(data, false);
                }
                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }

        /// <summary>
        /// Encrypts data using an RSA key.
        /// </summary>
        /// <param name="rsa">RSA public/private key pair.</param>
        /// <param name="data">Data to be encrypted.</param>
        /// <returns>Encrypted byte array.</returns>
        public static byte[] Encrypt(this RSA rsa, byte[] data)
        {
            try
            {
                byte[] encryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(rsa.ExportParameters(false));
                    encryptedData = RSA.Encrypt(data, false);
                }
                return encryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }
        #endregion
    }
}
