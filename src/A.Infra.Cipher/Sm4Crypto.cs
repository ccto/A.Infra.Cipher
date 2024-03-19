namespace A.Infra.Cipher
{
    /// <summary> 
    /// SM4 对称算法 
    /// UTF-8 编码解码
    /// </summary>
    public class Sm4Crypto
    {
        /// <summary> 随机生成SM4秘钥 16位 </summary>
        public static string GenerateSm4Key()
        {
            return Guid.NewGuid().ToString().Replace("-", string.Empty)[..16];
        }

        /// <summary> SM4加密 采用SM4/ECB/PKCS5Padding </summary>
        /// <param name="plaintext"> 明文 </param>
        /// <param name="sm4Key"> 密钥 </param>
        /// <returns> 密文 </returns>
        public static string Sm4Encrypt(string plaintext, string sm4Key)
        {
            byte[] sourceData = Encoding.UTF8.GetBytes(plaintext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(sm4Key);
            return Sm4Encrypt(sourceData, keyBytes);
        }

        /// <summary> SM4加密 采用SM4/ECB/PKCS5Padding </summary>
        /// <param name="sourceData"> 源数据 </param>
        /// <param name="keyBytes"> 密钥 </param>
        /// <returns> 密文 </returns>
        public static string Sm4Encrypt(byte[] sourceData, byte[] keyBytes)
        {
            var keyParam = ParameterUtilities.CreateKeyParameter("SM4", keyBytes);
            var inCipher = CipherUtilities.GetCipher("SM4/ECB/PKCS5Padding");
            inCipher.Init(true, keyParam);
            byte[] cipher = inCipher.DoFinal(sourceData);
            return Hex.ToHexString(cipher);
        }

        /// <summary> SM4解密 采用SM4/ECB/PKCS5Padding </summary>
        /// <param name="ciphertext"> 密文 </param>
        /// <param name="sm4Key"> 密钥 </param>
        /// <returns> UTF-8 解码的字符串 </returns>
        public static string Sm4Decrypt(string ciphertext, string sm4Key)
        {
            byte[] sourceData = Hex.Decode(ciphertext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(sm4Key);
            return Sm4Decrypt(sourceData, keyBytes);
        }

        /// <summary> SM4解密 采用SM4/ECB/PKCS5Padding </summary>
        /// <param name="sourceData"> 源数据 </param>
        /// <param name="keyBytes"> 密钥 </param>
        /// <returns> UTF-8 解码的字符串 </returns>
        public static string Sm4Decrypt(byte[] sourceData, byte[] keyBytes)
        {
            var keyParam = ParameterUtilities.CreateKeyParameter("SM4", keyBytes);
            var outCipher = CipherUtilities.GetCipher("SM4/ECB/PKCS5Padding");
            outCipher.Init(false, keyParam);
            byte[] cipher = outCipher.DoFinal(sourceData);
            return Encoding.UTF8.GetString(cipher);
        }
    }
}
