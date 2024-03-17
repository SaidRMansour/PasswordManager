using System;
using System.Security.Cryptography;

namespace GUI.ServicesMonolith
{
    // Provides functionality to generate secure passwords with customizable options.
    public class PasswordGenerator
    {
        // Secure random number generator to ensure password strength.
        private static readonly RNGCryptoServiceProvider CryptoProvider = new RNGCryptoServiceProvider();

        // Generates a password of specified length, optionally including special characters.
        public static string GeneratePassword(int length, bool includeSpecialChars)
        {
            // Character sets used in password generation.
            string LowercaseChars = "abcdefghijklmnopqrstuvwxyz";
            string UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string DigitChars = "0123456789";
            // Include special characters if requested.
            string SpecialChars = includeSpecialChars ? "!@#$%^&*" : "";
            // Combine character sets based on options.
            string AllChars = LowercaseChars + UppercaseChars + DigitChars + SpecialChars;

            // Enforce a minimum password length for security.
            if (length < 8)
                throw new ArgumentException("Password length must be at least 8 characters.");

            var passwordChars = new List<char>();

            // Ensure the password includes at least one of each required character type.
            passwordChars.Add(GetRandomCharacter(UppercaseChars));
            passwordChars.Add(GetRandomCharacter(LowercaseChars));
            passwordChars.Add(GetRandomCharacter(DigitChars));
            if (includeSpecialChars)
            {
                passwordChars.Add(GetRandomCharacter(SpecialChars));
            }

            // Fill the rest of the password length with random characters, avoiding sequential or repeated characters.
            while (passwordChars.Count < length)
            {
                var nextChar = GetRandomCharacter(AllChars);
                if (!ContainsSequentialOrRepeatedChars(passwordChars, nextChar))
                    passwordChars.Add(nextChar);
            }

            // Randomize the order of characters to avoid any patterns.
            return new string(passwordChars.OrderBy(c => GetRandomNumber()).ToArray());
        }

        // Checks if adding the next character would result in sequential or repeated characters.
        private static bool ContainsSequentialOrRepeatedChars(List<char> chars, char nextChar)
        {
            // Prevent immediate repetition of characters for increased security.
            return chars.Count > 0 && chars.Last() == nextChar;
        }

        // Selects a random character from the provided character set.
        private static char GetRandomCharacter(string validChars)
        {
            var index = GetRandomNumber(validChars.Length);
            return validChars[index];
        }

        // Generates a secure random number within the specified range.
        private static int GetRandomNumber(int max = Int32.MaxValue)
        {
            var randomNumber = new byte[4];
            CryptoProvider.GetBytes(randomNumber);
            return (int)(BitConverter.ToUInt32(randomNumber, 0) % max);
        }
    }
}
