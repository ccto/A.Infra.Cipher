namespace A.Infra.Cipher
{
    /// <summary> 
    /// SM3 杂凑算法 
    /// UTF-8 编码解码
    /// </summary>
    public static class Sm3Crypto
    {
        /// <summary> SM3加密 </summary>
        /// <param name="plaintext"> 明文 </param>
        /// <param name="key"> 自定义密钥 </param>
        /// <returns> 二进制数组 </returns>
        public static byte[] ToSM3HexByte(this string plaintext, string key)
        {
            byte[] sourceData = Encoding.UTF8.GetBytes(plaintext);
            byte[] secret = Encoding.UTF8.GetBytes(key);

            var keyParameter = new KeyParameter(secret);
            var sm3 = new SM3Digest();

            var cipher = new HMac(sm3); // 带密钥的杂凑算法
            cipher.Init(keyParameter);
            cipher.BlockUpdate(sourceData, 0, sourceData.Length);
            byte[] result = new byte[cipher.GetMacSize()];
            cipher.DoFinal(result, 0);
            return result;
        }

        /// <summary> SM3加密 </summary>
        /// <param name="plaintext"> 明文 </param>
        /// <param name="key"> 自定义密钥 </param>
        /// <returns> 字符串（十六进制编码） </returns>
        public static string ToSM3HexStr(this string plaintext, string key)
        {
            return Hex.ToHexString(plaintext.ToSM3HexByte(key));
        }

        /// <summary> SM3加密 </summary>
        /// <param name="plaintext"> 明文 </param>
        /// <returns> 二进制数组 </returns>
        public static byte[] ToSM3HexByte(this string plaintext)
        {
            var sourceData = Encoding.UTF8.GetBytes(plaintext);
            var sm3 = new SM3Digest();
            sm3.BlockUpdate(sourceData, 0, sourceData.Length);
            byte[] result = new byte[sm3.GetDigestSize()]; // SM3算法产生的哈希值大小
            sm3.DoFinal(result, 0);
            return result;
        }

        /// <summary> SM3加密 </summary>
        /// <param name="plaintext"> 明文 </param>
        /// <returns> 字符串（十六进制编码） </returns>
        public static string ToSM3HexStr(this string plaintext)
        {
            return Hex.ToHexString(plaintext.ToSM3HexByte());
        }
    }
}
