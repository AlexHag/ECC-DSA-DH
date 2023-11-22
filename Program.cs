using System;
using System.Text.Json;
using EccDsaDh.Models;

namespace EccDsaDh;

public class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Starting...");
        var alice = JsonSerializer.Deserialize<KeyPair>(File.ReadAllText("alice.json"));
        var bob = JsonSerializer.Deserialize<KeyPair>(File.ReadAllText("bob.json"));

        var encryptedMessage = CryptoService.EncryptMessage(alice, "Hello bob", bob.PublicKey);
        encryptedMessage.Signature = Reverse(encryptedMessage.Signature);
        Console.Write("Message was encrypted: ");
        PrintObj(encryptedMessage);
        var validation = CryptoService.DecryptMessage(encryptedMessage, bob.PrivateKey, out string message);

        Console.WriteLine(validation);
        Console.WriteLine(message);
    }
    
    private static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                            .ToArray();
    }

    public static string SerializeObj(object obj)
        => JsonSerializer.Serialize(obj, new JsonSerializerOptions{ WriteIndented = true });

    public static void PrintObj(object obj)
        => Console.WriteLine(JsonSerializer.Serialize(obj, new JsonSerializerOptions{ WriteIndented = true }));

    public static string Reverse( string s )
    {
        char[] charArray = s.ToCharArray();
        Array.Reverse(charArray);
        return new string(charArray);
    }
}


