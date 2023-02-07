using System;

namespace PauliECProgram;

public class Program
{
    public static void Main(string[] args)
    {
        var Alice = new ECMin();
        Alice.ImportPrivateKeyHex("AD4AC791DD74D1B9977E71677B0092AB85CB8C0121D0202CA617DE67B5742391");
        
        var Bob = new ECMin();
        Bob.ImportPrivateKeyHex("166A9098648FD8DFF07968235F032652B8A7ABB128C102173AC5EBC3D652E159");

        var Message = "Hello, world!";

        var Cipher = Alice.EncryptDH(Message, Bob.ExportPublicKeyHex());
        Console.WriteLine(Cipher);
        
        var OriginalMessage = Bob.DecryptDH(Cipher, Alice.ExportPublicKeyHex());
        Console.WriteLine(OriginalMessage);

        var Signature = Alice.SignMessage(Message);
        Console.WriteLine(Signature);

        var IsValid = ECMin.VerifyMessage(Message, Signature, Alice.ExportPublicKeyHex());
        Console.WriteLine(IsValid);
    }
}


