using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        while (true)
        {
            Console.WriteLine("Seleccione una opción:");
            Console.WriteLine("1. Generar par de claves");
            Console.WriteLine("2. Firmar mensaje");
            Console.WriteLine("3. Verificar firma");
            Console.WriteLine("4. Salir");
            Console.Write("Opción: ");

            int opcion;
            if (int.TryParse(Console.ReadLine(), out opcion))
            {
                switch (opcion)
                {
                    case 1:
                        GenerarParDeClaves();
                        break;
                    case 2:
                        FirmarMensaje();
                        break;
                    case 3:
                        VerificarFirma();
                        break;
                    case 4:
                        Console.WriteLine("Saliendo del programa.\n");
                        return;
                    default:
                        Console.WriteLine("Opción no válida.\n");
                        break;
                }
            }
            else
            {
                Console.WriteLine("Entrada no válida.\n");
            }
        }
    }

    static void GenerarParDeClaves()
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            RSAParameters privateKey = rsa.ExportParameters(true);
            RSAParameters publicKey = rsa.ExportParameters(false);

            File.WriteAllText("publicKey.txt", ToXmlString(publicKey));
            File.WriteAllText("privateKey.txt", ToXmlString(privateKey));
            Console.WriteLine("Par de claves generado y claves guardadas en 'publicKey.txt' y 'privateKey.txt'.");
        }
    }

    static void FirmarMensaje()
    {
        Console.Write("Ingrese el mensaje a firmar: ");
        string mensaje = Console.ReadLine();

        if (!File.Exists("privateKey.txt"))
        {
            Console.WriteLine("No se encontró la clave privada. Por favor, genere un par de claves primero.");
            return;
        }

        string privateKeyXml = File.ReadAllText("privateKey.txt");

        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.FromXmlString(privateKeyXml);

            byte[] mensajeBytes = System.Text.Encoding.UTF8.GetBytes(mensaje);
            byte[] firma = rsa.SignData(mensajeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            File.WriteAllBytes("firma.txt", firma);
            Console.WriteLine("Mensaje firmado y firma guardada en 'firma.txt'.");
        }
    }

    static void VerificarFirma()
    {
        Console.Write("Ingrese el mensaje original: ");
        string mensajeOriginal = Console.ReadLine();

        Console.Write("Ingrese la firma: ");
        byte[] firma = File.ReadAllBytes("firma.txt");

        if (!File.Exists("publicKey.txt"))
        {
            Console.WriteLine("No se encontró la clave pública. Por favor, genere un par de claves primero.");
            return;
        }

        string publicKeyXml = File.ReadAllText("publicKey.txt");

        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.FromXmlString(publicKeyXml);

            byte[] mensajeBytes = System.Text.Encoding.UTF8.GetBytes(mensajeOriginal);
            bool verificado = rsa.VerifyData(mensajeBytes, firma, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            if (verificado)
            {
                Console.WriteLine("La firma es válida.");
            }
            else
            {
                Console.WriteLine("La firma es inválida.");
            }
        }
    }

    static string ToXmlString(RSAParameters rsaParameters)
    {
        using (var sw = new System.IO.StringWriter())
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, rsaParameters);
            return sw.ToString();
        }
    }
}
