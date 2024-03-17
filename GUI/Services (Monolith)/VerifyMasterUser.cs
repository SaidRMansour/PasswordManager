using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GUI.Models;

namespace GUI.ServicesMonolith
{
    // Manages user verification, password encryption/decryption, and user data persistence.
    public class VerifyMasterUser
    {
        // Path to the JSON file storing master user data.
        private const string MasterUserFilePath = "./master_user.json";
        // A predefined value to verify the encryption and decryption process.
        private const string knownValue = "Secret123!1!";

        // Verifies the master user's credentials or initializes them if not already set.
        public (bool isValid, string? key) InitializeOrVerifyMasterUser(string email, string password)
        {
            // Hashes the email for secure storage.
            var emailHashed = ComputeSha256Hash(email);
            MasterUser masterUser;

            // Loads or initializes master user data.
            if (System.IO.File.Exists(MasterUserFilePath))
            {
                var userDataJson = System.IO.File.ReadAllText(MasterUserFilePath);
                masterUser = JsonSerializer.Deserialize<MasterUser>(userDataJson);
            }
            else
            {
                // For new setups: generates salt, encryption key, and stores them with the hashed email.
                var salt = EncryptionService.GenerateSalt();
                var key = EncryptionService.GenerateKey(password, salt);
                byte[] iv;
                var encryptedKnownValue = EncryptionService.EncryptData(knownValue, key, out iv);

                masterUser = new MasterUser
                {
                    EmailHash = emailHashed,
                    Salt = Convert.ToBase64String(salt),
                    IV = Convert.ToBase64String(iv),
                    EncryptedKnownValue = Convert.ToBase64String(encryptedKnownValue)
                };

                var masterUserJson = JsonSerializer.Serialize(masterUser);
                System.IO.File.WriteAllText(MasterUserFilePath, masterUserJson);
            }

            // Validates the user by decrypting a known value with the derived key.
            var inputKey = EncryptionService.GenerateKey(password, Convert.FromBase64String(masterUser.Salt));
            var decryptedKnownValue = EncryptionService.DecryptData(Convert.FromBase64String(masterUser.EncryptedKnownValue), inputKey, Convert.FromBase64String(masterUser.IV));
            bool isValid = decryptedKnownValue == knownValue && masterUser.EmailHash == emailHashed;
            return (isValid, Convert.ToBase64String(inputKey));
        }

        // Computes SHA-256 hash of the provided data.
        public static string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                foreach (var byteValue in bytes)
                {
                    builder.Append(byteValue.ToString("x2"));
                }
                return builder.ToString();
            }
        }

        // Adds an encrypted password entry to the master user data.
        public void AddEncryptedPassword(string encryptedPasswordBase64, string ivBase64)
        {
            var masterUserJson = System.IO.File.ReadAllText(MasterUserFilePath);
            var masterUser = JsonSerializer.Deserialize<MasterUser>(masterUserJson);

            if (masterUser != null)
            {
                masterUser.EncryptedPasswords.Add(new EncryptedPasswordEntry
                {
                    EncryptedPassword = encryptedPasswordBase64,
                    IV = ivBase64
                });
                masterUserJson = JsonSerializer.Serialize(masterUser, new JsonSerializerOptions { WriteIndented = true });
                System.IO.File.WriteAllText(MasterUserFilePath, masterUserJson);
            }
            else
            {
                throw new InvalidOperationException("Unable to load or deserialize the master user data.");
            }
        }

        // Decrypts and returns all passwords stored for the user.
        public List<string> GetDecryptedPasswords(byte[] encryptionKey)
        {
            var decryptedPasswords = new List<string>();
            var masterUserJson = File.ReadAllText(MasterUserFilePath);
            var masterUser = JsonSerializer.Deserialize<MasterUser>(masterUserJson);

            if (masterUser != null)
            {
                foreach (var entry in masterUser.EncryptedPasswords)
                {
                    var decryptedPassword = EncryptionService.DecryptData(Convert.FromBase64String(entry.EncryptedPassword), encryptionKey, Convert.FromBase64String(entry.IV));
                    decryptedPasswords.Add(decryptedPassword);
                }
            }
            return decryptedPasswords;
        }

        // Decrypts and returns a single password at the specified index.
        public string GetDecryptedPasswordAt(int index, byte[] encryptionKey)
        {
            var masterUserJson = File.ReadAllText(MasterUserFilePath);
            var masterUser = JsonSerializer.Deserialize<MasterUser>(masterUserJson);

            if (masterUser == null || index < 0 || index >= masterUser.EncryptedPasswords.Count)
                throw new ArgumentException("Invalid index or user data not found.");

            var entry = masterUser.EncryptedPasswords[index];
            return EncryptionService.DecryptData(Convert.FromBase64String(entry.EncryptedPassword), encryptionKey, Convert.FromBase64String(entry.IV));
        }
    }
}
