namespace A.Infra.Cipher
{
    public class CryptoUtilities
    {
        /// <summary> 十六进制字符串转 byte[] </summary>
        public static byte[] Decode(string key)
        {
            return Regex.IsMatch(key, "^[0-9a-f]+$", RegexOptions.IgnoreCase) ? Hex.Decode(key) : Convert.FromBase64String(key);
        }

        /// <summary> byte[] 转十六进制字符串 </summary>
        public static string HexString(byte[] bytes)
        {
            return Hex.ToHexString(bytes);
        }
    }
}