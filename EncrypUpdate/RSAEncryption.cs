using System;
using System.IO;
using System.Security.Cryptography;

namespace EncrypUpdate
{
    public class RSAEncryption
    {
        public static string Encrypt(string value)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                string pubKey = File.ReadAllText("public-rsa-key.xml");
                csp.FromXmlStr(pubKey);
                var bytesPlainTextData = System.Text.Encoding.ASCII.GetBytes(value);
                var bytesCypherText = csp.Encrypt(bytesPlainTextData, false);
                var cypherText = Convert.ToBase64String(bytesCypherText);
                return cypherText;
            }
        }

        public static string Decrypt(string cypertext)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                string privateKey = File.ReadAllText("private-rsa-key.xml");
                csp.FromXmlStr(privateKey);
                byte[] value = Convert.FromBase64String(cypertext);
                byte[] result = csp.Decrypt(value, false);
                string plaintext = System.Text.Encoding.ASCII.GetString(result);
                return plaintext;
            }
        }
    }
}
