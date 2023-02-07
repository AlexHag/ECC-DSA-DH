using System.Security.Cryptography;
using System.Text;

public class ECMin
{
    private byte[]? PublicKey;
    private byte[]? PrivateKey;

    public void GenerateNewKeys()
    {
        using(ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            var KeyParameters = ecdsa.ExportParameters(true);
            PrivateKey = KeyParameters.D;
            byte[] xCoord = KeyParameters.Q.X;
            byte[] yCoord = KeyParameters.Q.Y;

            // byte prefix = (byte)((yCoord[yCoord.Length - 1] & 1) == 0 ? 0x02: 0x03);
            
            byte[] PublicPoint = new byte[xCoord.Length + yCoord.Length + 1];
            PublicPoint[0] = 0x04;
            Buffer.BlockCopy(xCoord, 0, PublicPoint, 1, xCoord.Length);
            Buffer.BlockCopy(yCoord, 0, PublicPoint, xCoord.Length + 1, yCoord.Length);
            PublicKey = PublicPoint;
        }
    }

    public string ExportPrivateKeyHex()
    {
        return BitConverter.ToString(PrivateKey).Replace("-", "");
    }

    public string ExportPublicKeyHex()
    {
        return BitConverter.ToString(PublicKey).Replace("-", "");
    }

    public void ImportPrivateKeyHex(string privateKeyHex)
    {
        using(ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            ecdsa.ImportParameters(new ECParameters{Curve = ECCurve.NamedCurves.nistP256, D = StringToByteArray(privateKeyHex)});
            var KeyParameters = ecdsa.ExportParameters(true);
            PrivateKey = KeyParameters.D;
            byte[] xCoord = KeyParameters.Q.X;
            byte[] yCoord = KeyParameters.Q.Y;
            
            // Compress theses points!!! god why is it so hard to import compressed keys fuck microsoft cng that nobody wants!!!!!!
            // byte prefix = (byte)((yCoord[yCoord.Length - 1] & 1) == 0 ? 0x02: 0x03);
            
            byte[] PublicPoint = new byte[xCoord.Length + yCoord.Length + 1];
            PublicPoint[0] = 0x04;
            Buffer.BlockCopy(xCoord, 0, PublicPoint, 1, xCoord.Length);
            Buffer.BlockCopy(yCoord, 0, PublicPoint, xCoord.Length + 1, yCoord.Length);
            PublicKey = PublicPoint;
        }
    }

    public void ImportPublicKeyHex(string publicKeyHex)
    {
        PublicKey = StringToByteArray(publicKeyHex);
        // var PublicKeyBytes = StringToByteArray(publicKeyHex);
        // using(ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        // {
        //     ecdsa.ImportParameters(new ECParameters
        //     {
        //         Curve = ECCurve.NamedCurves.nistP256,
        //         Q = new ECPoint
        //         {
        //             X = PublicKeyBytes.Skip(1).Take(32).ToArray(),
        //             Y = PublicKeyBytes.Skip(33).ToArray()
        //         }
        //     });
        // }


        // throw new NotImplementedException();
    }

    public string SignMessage(string Message)
    {
        if(PrivateKey == null) throw new ArgumentNullException("No private key");
        using(ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            ecdsa.ImportParameters(new ECParameters{Curve = ECCurve.NamedCurves.nistP256, D = PrivateKey});
            var MessageBytes = Encoding.ASCII.GetBytes(Message);
            
            var SignatureBytes = ecdsa.SignData(MessageBytes, HashAlgorithmName.SHA256);
            return BitConverter.ToString(SignatureBytes).Replace("-", string.Empty);
        }
    }

    public bool VerifyMessage(string Message, string Signature)
    {
        if(PublicKey == null) throw new ArgumentNullException("No private key");
        using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = PublicKey.Skip(1).Take(32).ToArray(),
                    Y = PublicKey.Skip(33).ToArray()
                }
            });
            return ecdsa.VerifyData(Encoding.ASCII.GetBytes(Message), StringToByteArray(Signature), HashAlgorithmName.SHA256);
        }
    }

    public static bool VerifyMessage(string Message, string Signature, string SubjectPublicKey)
    {
        using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = StringToByteArray(SubjectPublicKey).Skip(1).Take(32).ToArray(),
                    Y = StringToByteArray(SubjectPublicKey).Skip(33).ToArray()
                }
            });
            return ecdsa.VerifyData(Encoding.ASCII.GetBytes(Message), StringToByteArray(Signature), HashAlgorithmName.SHA256);
        }
    }

    public string EncryptDH(string Message, string RecipientPublicKey)
    {
        ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ecdh.ImportParameters(new ECParameters{Curve = ECCurve.NamedCurves.nistP256, D = PrivateKey});
        
        ECDiffieHellman recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        recipient.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = StringToByteArray(RecipientPublicKey).Skip(1).Take(32).ToArray(),
                Y = StringToByteArray(RecipientPublicKey).Skip(33).ToArray()
            }
        });

        byte[] SharedKey = ecdh.DeriveKeyMaterial(recipient.PublicKey);

        byte[] encryptedMessage = null;
        byte[] iv = null;
        
        Aes aes = new AesCryptoServiceProvider();
        aes.Key = SharedKey;
        iv = aes.IV;

        // Encrypt the message
        using (MemoryStream ciphertext = new MemoryStream())
        using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            byte[] plaintextMessage = Encoding.UTF8.GetBytes(Message);
            cs.Write(plaintextMessage, 0, plaintextMessage.Length);
            cs.Close();
            encryptedMessage = ciphertext.ToArray();
        }
        var FullCipher = BitConverter.ToString(iv).Replace("-", "") + "." + BitConverter.ToString(encryptedMessage).Replace("-", "");
        return FullCipher;
    }

    public string DecryptDH(string FullCipher, string SenderPublicKey)
    {
        ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ecdh.ImportParameters(new ECParameters{Curve = ECCurve.NamedCurves.nistP256, D = PrivateKey});
        
        ECDiffieHellman recipient = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        recipient.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = StringToByteArray(SenderPublicKey).Skip(1).Take(32).ToArray(),
                Y = StringToByteArray(SenderPublicKey).Skip(33).ToArray()
            }
        });

        byte[] SharedKey = ecdh.DeriveKeyMaterial(recipient.PublicKey);

        byte[] encryptedMessage = StringToByteArray(FullCipher.Split('.')[1]);
        byte[] iv = StringToByteArray(FullCipher.Split('.')[0]);
        using (Aes aes = new AesCryptoServiceProvider())
        {
            aes.Key = SharedKey;
            aes.IV = iv;
            // Decrypt the message
            using (MemoryStream plaintext = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                    cs.Close();
                    string message = Encoding.UTF8.GetString(plaintext.ToArray());
                    return message;
                }
            }
        }
    }

    public static byte[] StringToByteArray(string hex) {
    return Enumerable.Range(0, hex.Length)
                        .Where(x => x % 2 == 0)
                        .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                        .ToArray();
    }
}