using System;

namespace EncrypUpdate
{
    class Program
    {
        static void Main(string[] args)
        {
            EncryptionService encryptionService = new EncryptionService();

            string secretmsg = "hello people";
            byte[] nonce = encryptionService.Nonce();
            byte[] nonSecretPayload = encryptionService.GetTimestamp();
            string key = encryptionService.NewKey();


            string encryptMsg = encryptionService.EncryptWithKey(nonce, secretmsg, key, nonSecretPayload);
            Console.WriteLine(encryptMsg);
            string plaintext = encryptionService.DecryptWithKey(encryptMsg, key, nonSecretPayload.Length);
            Console.WriteLine(plaintext);

            Console.Read();
        }
    }
}
