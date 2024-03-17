using System;
namespace GUI.Models
{
	public class MasterUser
	{
        public string EmailHash { get; set; }
        public string Salt { get; set; }
        public string IV { get; set; }
        public string EncryptedKnownValue { get; set; }
        public List<EncryptedPasswordEntry> EncryptedPasswords { get; set; } = new List<EncryptedPasswordEntry>();

    }
}

