using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GUI.ServicesMonolith
{
    public static class EncryptionService
    {
        // Generates a random salt for hashing purposes.
        public static byte[] GenerateSalt()
        {
            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                var salt = new byte[16];
                randomNumberGenerator.GetBytes(salt);
                return salt;
            }
        }

        // Generates an encryption key from the master password and salt using PBKDF2.
        public static byte[] GenerateKey(string password, byte[] salt)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, 100000))
            {
                return deriveBytes.GetBytes(32); // Generates a 256-bit key.
            }
        }

        // Encrypts data using AES with a provided key and outputs the initialization vector (IV).
        public static byte[] EncryptData(string dataToEncrypt, byte[] key, out byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                iv = aes.IV;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(dataToEncrypt);
                    }

                    return ms.ToArray();
                }
                
            }
        }

        // Decrypts data using AES with a provided key and initialization vector (IV).
        public static string DecryptData(byte[] dataToDecrypt, byte[] key, byte[] iv)
        {
            try
            {
                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (var ms = new MemoryStream(dataToDecrypt))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
            catch (CryptographicException)
            {
                // Throws an exception to handle decryption failure scenarios.
                throw new InvalidLoginException(); 
            }
        }
    }
}
