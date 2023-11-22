using System.Security.Cryptography;
using System.Text;
using EccDsaDh.Models;

namespace EccDsaDh;

public static class CryptoService
{
    public static KeyPair GenerateKeyPair()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyParameters = ecdsa.ExportParameters(true);
        byte[] privateKey = keyParameters.D!;

        byte[] xCoord = keyParameters.Q.X!;
        byte[] yCoord = keyParameters.Q.Y!;

        byte[] publicKeyCoords = new byte[1 + xCoord.Length + yCoord.Length];

        // TODO: compress points
        // byte prefix = (byte)((yCoord[yCoord.Length - 1] & 1) == 0 ? 0x02: 0x03);
        byte prefix = 0x04;
        publicKeyCoords[0] = prefix;
        Buffer.BlockCopy(xCoord, 0, publicKeyCoords, 1, xCoord.Length);
        Buffer.BlockCopy(yCoord, 0, publicKeyCoords, xCoord.Length + 1, yCoord.Length);

        var keyContent = new KeyPair
        {
            PublicKey = BytesToHex(publicKeyCoords),
            PrivateKey = BytesToHex(privateKey)
        };
        return keyContent;
    }

    public static SignedMessage SignMessage(string privateKey, string message)
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ecdsa.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = HexToBytes(privateKey)
        });

        var keyParameters = ecdsa.ExportParameters(true);

        byte[] xCoord = keyParameters.Q.X!;
        byte[] yCoord = keyParameters.Q.Y!;

        byte[] publicKeyCoords = new byte[1 + xCoord.Length + yCoord.Length];

        // TODO: compress points
        // byte prefix = (byte)((yCoord[yCoord.Length - 1] & 1) == 0 ? 0x02: 0x03);
        byte prefix = 0x04;
        publicKeyCoords[0] = prefix;
        Buffer.BlockCopy(xCoord, 0, publicKeyCoords, 1, xCoord.Length);
        Buffer.BlockCopy(yCoord, 0, publicKeyCoords, xCoord.Length + 1, yCoord.Length);

        byte[] messageHash = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(message));
        var signature = ecdsa.SignData(messageHash, HashAlgorithmName.SHA256);

        var signedMessage = new SignedMessage
        {
            PublicKey = BytesToHex(publicKeyCoords),
            Signature = BytesToHex(signature),
            MessageHash = BytesToHex(messageHash)
        };

        return signedMessage;
    }

    public static bool VerifySignedMessage(SignedMessage message)
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = HexToBytes(message.PublicKey);
        ecdsa.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = publicKey.Skip(1).Take(32).ToArray(),
                Y = publicKey.Skip(33).ToArray()
            }
        });

        byte[] messageHash = HexToBytes(message.MessageHash);

        return ecdsa.VerifyData(
            messageHash,
            HexToBytes(message.Signature),
            HashAlgorithmName.SHA256);
    }

    public static EncryptedMessage EncryptMessage(KeyPair keyPair, string message, string recipienPublicKey)
    {
        byte[] sharedKey = ECDH(HexToBytes(keyPair.PrivateKey), HexToBytes(recipienPublicKey));

        var aes = Aes.Create();
        aes.Key = sharedKey;
        byte[] iv = aes.IV;

        using var cipherStream = new MemoryStream();
        using var cs = new CryptoStream(cipherStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        cs.Write(messageBytes, 0, messageBytes.Length);
        cs.Close();
        
        byte[] cipherBytes = cipherStream.ToArray();
        string cipher = BytesToHex(iv) + "." + BytesToHex(cipherBytes);

        var signature = SignMessage(keyPair.PrivateKey, message);

        var encryptedMessage = new EncryptedMessage
        {
            SenderPublicKey = keyPair.PublicKey,
            RecipientPublicKey = recipienPublicKey,
            Cipher = cipher,
            Signature = signature.Signature
        };

        return encryptedMessage;
    }

    public static bool DecryptMessage(EncryptedMessage encryptedMessage, string privateKey, out string message)
    {
        byte[] sharedKey = ECDH(HexToBytes(privateKey), HexToBytes(encryptedMessage.SenderPublicKey));

        byte[] iv = HexToBytes(encryptedMessage.Cipher.Split(".")[0]);
        byte[] cipherBytes = HexToBytes(encryptedMessage.Cipher.Split(".")[1]);

        var aes = Aes.Create();
        aes.Key = sharedKey;
        aes.IV = iv;

        using var plaintextStream = new MemoryStream();
        using var cs = new CryptoStream(plaintextStream, aes.CreateDecryptor(), CryptoStreamMode.Write);
        cs.Write(cipherBytes, 0, cipherBytes.Length);
        cs.Close();
        var messageBytes = plaintextStream.ToArray();

        var messageHash = SHA256.Create().ComputeHash(messageBytes);
        message = Encoding.UTF8.GetString(messageBytes);

        var signature = new SignedMessage
        {
            PublicKey = encryptedMessage.SenderPublicKey,
            Signature = encryptedMessage.Signature,
            MessageHash = BytesToHex(messageHash)
        };

        var validation = VerifySignedMessage(signature);
        return validation;
    }

    private static byte[] ECDH(byte[] privateKey, byte[] publicKey)
    {
        ECDiffieHellman alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        alice.ImportParameters(new ECParameters 
        { 
            Curve = ECCurve.NamedCurves.nistP256, 
            D = privateKey,
        });

        ECDiffieHellman bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        bob.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = publicKey.Skip(1).Take(32).ToArray(),
                Y = publicKey.Skip(33).ToArray()
            }
        });

        byte[] sharedKey = alice.DeriveKeyMaterial(bob.PublicKey);
        return sharedKey;
    }

    private static byte[] HexToBytes(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                            .ToArray();
    }

    private static string BytesToHex(byte[] bytes)
        => BitConverter.ToString(bytes).Replace("-", "");
}