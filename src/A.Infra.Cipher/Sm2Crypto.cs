namespace A.Infra.Cipher
{
    /// <summary> 
    /// SM2 椭圆曲线公钥密码算法 
    /// UTF-8 编码解码
    /// 标准 C1C2C3 （Curves：SM2P256V1）
    /// 返回字符串（或 byte[] ）十六进制编码
    /// </summary>
    public sealed class Sm2Crypto
    {
        /// <summary> 生成SM2公钥私钥 </summary>
        /// <param name="publicKey"> SM2公钥 16进制 </param>
        /// <param name="privateKey"> SM2私钥 16进制 </param>
        public static void GenerateSm2KeyHex(out string publicKey, out string privateKey)
        {
            GenerateSm2Key(out var a, out var b);
            publicKey = Hex.ToHexString(a);
            privateKey = Hex.ToHexString(b);
        }

        /// <summary> 生成SM2公钥私钥 </summary>
        /// <param name="publicKey"> SM2公钥 </param>
        /// <param name="privateKey"> SM2私钥 </param>
        public static void GenerateSm2Key(out byte[] publicKey, out byte[] privateKey)
        {
            var g = new ECKeyPairGenerator();
            g.Init(new ECKeyGenerationParameters(new ECDomainParameters(GMNamedCurves.GetByName("SM2P256V1")), new SecureRandom()));
            var k = g.GenerateKeyPair();
            publicKey = ((ECPublicKeyParameters)k.Public).Q.GetEncoded(false);
            privateKey = ((ECPrivateKeyParameters)k.Private).D.ToByteArray();
        }

        /// <summary> SM2加密 </summary>
        /// <param name="plaintext"> 明文 </param>
        /// <param name="publicKey"> 公钥 </param>
        /// <returns> 十六进制字符串 </returns>
        public static string Sm2Encrypt(string plaintext, string publicKey)
        {
            return Hex.ToHexString(Sm2Encrypt(Encoding.UTF8.GetBytes(plaintext), Hex.Decode(publicKey)));
        }

        /// <summary> SM2加密 </summary>
        /// <param name="sourceData"> 数据源 </param>
        /// <param name="publicKey"> 公钥 </param>
        /// <returns> 二进制数组 </returns>
        public static byte[] Sm2Encrypt(byte[] sourceData, byte[] publicKey)
        {
            var x9ec = GMNamedCurves.GetByName("SM2P256V1");
            ICipherParameters publicKeyParameters = new ECPublicKeyParameters(
                x9ec.Curve.DecodePoint(publicKey),
                new ECDomainParameters(x9ec));

            var sm2 = new SM2Engine(new SM3Digest());
            sm2.Init(true, new ParametersWithRandom(publicKeyParameters));
            return sm2.ProcessBlock(sourceData, 0, sourceData.Length);
        }

        /// <summary> SM2解密 </summary>
        /// <param name="ciphertext"> 密文 </param>
        /// <param name="privkey"> 私钥 </param>
        /// <returns> UTF-8 解码字符串 </returns>
        public static string Sm2Decrypt(string ciphertext, string privkey)
        {
            return Encoding.UTF8.GetString(Sm2Decrypt(Hex.Decode(ciphertext), Hex.Decode(privkey)));
        }

        /// <summary> SM2解密 </summary>
        /// <param name="sourceData"> 数据源 </param>
        /// <param name="privateKey"> 私钥 </param>
        /// <returns> 二进制数组 </returns>
        public static byte[] Sm2Decrypt(byte[] sourceData, byte[] privateKey)
        {
            var x9ec = GMNamedCurves.GetByName("SM2P256V1");
            var privateKeyParameters = new ECPrivateKeyParameters(
                new BigInteger(1, privateKey),
                new ECDomainParameters(x9ec));

            var sm2 = new SM2Engine(new SM3Digest());
            sm2.Init(false, privateKeyParameters);
            byte[] res = sm2.ProcessBlock(sourceData, 0, sourceData.Length);
            return res;
        }

        /// <summary> 加签算法 标准C1C2C3模式 </summary>
        /// <param name="content"> 内容 </param>
        /// <param name="privateKey"> 私钥 </param>
        /// <param name="timestamp"> 时间戳 </param>
        /// <returns> 签名数据（十六进制编码） </returns>
        public static string Sign(string content, string privateKey, out string timestamp)
        {
            timestamp = DateTime.Now.ToString();
            return Hex.ToHexString(Sign(Encoding.UTF8.GetBytes(content), Hex.Decode(privateKey), Encoding.UTF8.GetBytes(timestamp)));
        }

        /// <summary> 加签算法 标准C1C2C3模式 </summary>
        /// <param name="sourceData"> 源数据 </param>
        /// <param name="privateKey"> 私钥 </param>
        /// <param name="userId"> 用户标识 </param>
        /// <returns> 签名数据 </returns>
        public static byte[] Sign(byte[] sourceData, byte[] privateKey, byte[]? userId = null)
        {
            var privateKeyParameters = new ECPrivateKeyParameters(
                new BigInteger(1, privateKey),
                new ECDomainParameters(GMNamedCurves.GetByName("SM2P256V1")));
            var sm2 = new SM2Signer(new SM3Digest());
            ICipherParameters cp;
            if (userId != null) cp = new ParametersWithID(new ParametersWithRandom(privateKeyParameters), userId);
            else cp = new ParametersWithRandom(privateKeyParameters);
            sm2.Init(true, cp);
            sm2.BlockUpdate(sourceData, 0, sourceData.Length);
            return sm2.GenerateSignature();
        }

        /// <summary> 验签算法 标准C1C2C3模式 </summary>
        /// <param name="content"> 内容 </param>
        /// <param name="privateKey"> 私钥 </param>
        /// <param name="timestamp"> 时间戳 </param>
        /// <returns> 验证成功；验证失败（true；false） </returns>
        public static bool VerifySign(string content, string publicKey, string sign, string timestamp)
        {
            return VerifySign(Encoding.UTF8.GetBytes(content), Hex.Decode(publicKey), Hex.Decode(sign), Encoding.UTF8.GetBytes(timestamp));
        }

        /// <summary> 验签算法 标准C1C2C3模式 </summary>
        /// <param name="sourceData"> 源数据 </param>
        /// <param name="publicKey"> 公钥 </param>
        /// <param name="signData"> 验签数据 </param>
        /// <param name="userId"> 用户标识 </param>
        /// <returns> 验证成功；验证失败（true；false） </returns>
        public static bool VerifySign(byte[] sourceData, byte[] publicKey, byte[] signData, byte[]? userId = null)
        {
            var x9ec = GMNamedCurves.GetByName("SM2P256V1");
            ICipherParameters publicKeyParameters = new ECPublicKeyParameters(
                x9ec.Curve.DecodePoint(publicKey),
                new ECDomainParameters(x9ec));
            var sm2 = new SM2Signer(new SM3Digest());
            ICipherParameters cp;
            if (userId != null) cp = new ParametersWithID(publicKeyParameters, userId);
            else cp = publicKeyParameters;
            sm2.Init(false, cp);
            sm2.BlockUpdate(sourceData, 0, sourceData.Length);
            return sm2.VerifySignature(signData);
        }

        ///// <summary>
        ///// 签名，国密SM2
        ///// </summary>
        ///// <param name="body">参数内容</param>
        ///// <param name="privateKey">私钥</param>
        ///// <param name="sign">签名值</param>
        ///// <param name="timestamp">时间戳</param>
        //public void Sign(string body, string privateKey, out string sign, out string timestamp)
        //{
        //    //if (body.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(body));
        //    //if (privateKey.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(privateKey));

        //    timestamp = PSUtils.GetTimeStamp();

        //    // 加密算法采用SM2加密算法
        //    sign = SMCrypto.HexString(SMCrypto.Sign(Encoding.UTF8.GetBytes(body), SMCrypto.Decode(privateKey), Encoding.UTF8.GetBytes(timestamp)));
        //}

        ///// <summary>
        ///// 验签，国密SM2
        ///// </summary>
        ///// <param name="body">参数内容</param>
        ///// <param name="publicKey">公约</param>
        ///// <param name="sign">签名值</param>
        ///// <param name="timestamp">时间戳</param>
        ///// <returns>成功与否</returns>
        //public bool VerifySign(string body, string publicKey, string sign, string timestamp)
        //{
        //    //if (body.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(body));
        //    //if (publicKey.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(publicKey));
        //    //if (sign.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(sign));
        //    //if (timestamp.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(timestamp));

        //    return SMCrypto.VerifySign(Encoding.UTF8.GetBytes(body), SMCrypto.Decode(publicKey), SMCrypto.Decode(sign),
        //         Encoding.UTF8.GetBytes(timestamp));
        //}
    }
}
