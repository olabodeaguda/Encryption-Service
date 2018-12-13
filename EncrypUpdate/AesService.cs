using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Text;

namespace EncrypUpdate
{
    public class AesService
    {

        public static readonly int NonceBitSize = 64;
        public static readonly int MacBitSize = 128;
        public static readonly int KeyBitSize = 128;

        private static byte[] GetKey()
        {
            string key = "AAAAIQCkYQpBcyXai9NJIkQu53g2sqMcE8j95g67632VFF/ViQAAABEA7GldDpMiOfMs1PtUIO+BswAAABEAx5MgUHPZ0BM4hhrh8Yv/FwAAABEAzD60H305ycWlPub0Da41vg==";
            var bytes = Encoding.UTF8.GetBytes(key);
            byte[] results = new byte[16];
            Array.Copy(bytes, 0, results, 0, 16);
            return results;
        }

        private static byte[] GetIV()
        {
            byte[] results = new byte[16];
            Array.Copy(GetKey(), 0, results, 0, 16);
            return results;
        }

        public static byte[] GetTimestamp()
        {
            long unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string tmeSpan = unixTime.ToString(); // DateTimeOffset.Now.ToString("yyyyMMddHHmmssffff");
            var bytes = Encoding.UTF8.GetBytes(tmeSpan);
            return bytes;
        }

        public static byte[] SimpleEncrypt(byte[] secretMessage, byte[] nonSecretPayload = null)
        {
            byte[] key = GetKey();
            //User Error Checks
            if (key == null || key.Length != KeyBitSize / 8)
            {
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "key");
            }

            if (secretMessage == null || secretMessage.Length == 0)
            {
                throw new ArgumentException("Secret Message Required!", "secretMessage");
            }

            //Non-secret Payload Optional
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            //Using random nonce large enough not to repeat
            var nonce = key;

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), MacBitSize, nonce, nonSecretPayload);
           
            cipher.Init(true, parameters);

            //Generate Cipher Text With Auth Tag
            var cipherText = new byte[cipher.GetOutputSize(secretMessage.Length)];
            var len = cipher.ProcessBytes(secretMessage, 0, secretMessage.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Authenticated Payload
                    binaryWriter.Write(nonSecretPayload);
                    //Prepend Nonce
                    binaryWriter.Write(nonce);
                    //Write Cipher Text
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }


        public static string DecryptWithKey(byte[] encryptedMessage, int nonSecretPayloadLength = 0)
        {
            byte[] key = GetKey();
           
            if (encryptedMessage == null || encryptedMessage.Length == 0)
            {
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            }

            using (var cipherStream = new MemoryStream(encryptedMessage))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                //Grab Payload
                var nonSecretPayload = cipherReader.ReadBytes(nonSecretPayloadLength);

                //Grab Nonce
                var nonce = key;

                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(key), MacBitSize, nonce, nonSecretPayload);
                cipher.Init(false, parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length - nonSecretPayloadLength - nonce.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

                var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                cipher.DoFinal(plainText, len);

                return Encoding.UTF8.GetString(plainText);
            }
        }
    }
}
