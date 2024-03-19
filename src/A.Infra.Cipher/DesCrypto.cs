namespace A.Infra.Cipher
{
    /// <summary>
    /// DES 加密算法
    /// 对称密钥，密钥长度64位
    /// </summary>
    public class DesCrypto
    {
        /// <summary> Des加密 </summary>
        /// <param name="plaintext"> 字符串明文 </param>
        /// <param name="key"> 密钥 </param>
        /// <returns> 字符串密文（Base64字符串） </returns>
        public static string DesEncrypt(string plaintext, string key)
        {
            var sourceData = Encoding.UTF8.GetBytes(plaintext);
            var keyParam = ParameterUtilities.CreateKeyParameter("DES", Convert.FromBase64String(key));
            var cipher = (BufferedBlockCipher)CipherUtilities.GetCipher("DES/NONE/PKCS5Padding");

            cipher.Init(true, keyParam);
            var rst = cipher.DoFinal(sourceData);
            return Convert.ToBase64String(rst);
        }

        /// <summary> Des解密 </summary>
        /// <param name="base64String"> 字符串密文（Base64字符串） </param>
        /// <param name="key"> 密钥 </param>
        /// <returns> 字符串明文 </returns>
        public static string DesDecrypt(string base64String, string key)
        {
            var bs = Convert.FromBase64String(base64String);
            var keyParam = ParameterUtilities.CreateKeyParameter("DES", Convert.FromBase64String(key));
            var cipher = (BufferedBlockCipher)CipherUtilities.GetCipher("DES/NONE/PKCS5Padding");

            cipher.Init(false, keyParam);
            var rst = cipher.DoFinal(bs);
            return Encoding.UTF8.GetString(rst);
        }
    }
}
