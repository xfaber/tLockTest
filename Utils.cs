using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static mcl.MCL;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;

namespace tLockTest
{
  public static class CryptoUtils
  {

    // Metodo per verificare se un numero è un generatore per un gruppo di ordine primo
    public static bool IsGenerator(System.Numerics.BigInteger number, int order)
    {
      if (number <= 1 || number >= order)
        return false; // Il numero deve essere compreso tra 1 e (ordine - 1)

      // Calcola (number ^ (ordine - 1)) % ordine
      var result = System.Numerics.BigInteger.ModPow(number, order - 1, order);

      // Se il risultato è 1, allora il numero è un generatore
      return result == 1;
    }

    /// <summary>
    /// Restituise il generatore di un gruppo di ordine primo q
    /// </summary>
    /// <param name="q"></param>
    /// <returns></returns>
    public static System.Numerics.BigInteger GetGenerator(System.Numerics.BigInteger q)
    {
      //int q = 7; // Sostituisci con il tuo ordine primo
      int generator = -1; // Inizializza a un valore che indica che il generatore non è stato trovato
          
      for (var a = 2; a < q; a++)
      {
        bool isGenerator = true;

        for (int i = 1; i <= q - 2; i++) // Itera su tutti i possibili esponenti da 1 a q-2
        {
          System.Numerics.BigInteger result = ModuloExponentiation(a, i, q);

          if (result == 1)
          {
            isGenerator = false;
            break;
          }
        }

        if (isGenerator)
        {
          generator = a;
          break;
        }
      }

      if (generator != -1)
      {
        Console.WriteLine($"Il generatore del gruppo ciclico Z/{q}Z è {generator}");
      }
      else
      {
        Console.WriteLine($"Nessun generatore trovato per il gruppo ciclico Z/{q}Z");
      }

      return generator;
    }

    // Funzione di esponenziazione modulare
    public static System.Numerics.BigInteger ModuloExponentiation(System.Numerics.BigInteger baseValue, int exponent, System.Numerics.BigInteger modulus)
    {
      System.Numerics.BigInteger result = 1;

      while (exponent > 0)
      {
        if (exponent % 2 == 1)
        {
          result = (result * baseValue) % modulus;
        }

        baseValue = (baseValue * baseValue) % modulus;
        exponent /= 2;
      }

      return result;
    }

    public static byte[] GetRndBytes(int length)
    {
      //var sigma = GetSecureRandomNumber(length * 8);
      //var b = sigma.ToByteArray();

      Random rnd = new Random();
      Byte[] b = new Byte[length];
      rnd.NextBytes(b);
      return b;
    }

    public static byte[] FromHexStr(string s)
    {
      if (s.Length % 2 == 1)
      {
        throw new ArgumentException("s.Length is odd." + s.Length);
      }
      int n = s.Length / 2;
      var buf = new byte[n];
      for (int i = 0; i < n; i++)
      {
        buf[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
      }
      return buf;
    }
    public static string ToCompressedPoint(this G1 ecPoint)
    {
      byte[] compressedPoint = ecPoint.Serialize();
      return BitConverter.ToString(compressedPoint).Replace("-", string.Empty);
    }

    public static string ToCompressedPoint(this G2 ecPoint)
    {
      byte[] compressedPoint = ecPoint.Serialize();
      return BitConverter.ToString(compressedPoint).Replace("-", string.Empty);
    }

    /// <summary>
    /// Genera un numero casuale
    /// </summary>
    /// <param name="bitLength">Lunghezza del numero casuale in bit</param>
    /// <returns></returns>
    public static BigInteger GetSecureRandomNumber(int bitLength = 256)
    { 
      byte[] randomNumber = RandomNumberGenerator.GetBytes(bitLength / 8);
      var randomBigInteger = new BigInteger(randomNumber);

      // Converte il numero casuale in una rappresentazione esadecimale per la visualizzazione
      //string randomHex = BitConverter.ToString(randomNumber).Replace("-", "");
      return randomBigInteger;
    }

    /// <summary>
    /// Calcola l'hash usando SHA256
    /// </summary>
    /// <param name="aBytes"></param>
    /// <returns></returns>
    public static byte[] GetSHA256(byte[] aBytes)
    {
      var H = new Sha256Digest();
      H.BlockUpdate(aBytes, 0, aBytes.Length);
      var hash = new byte[H.GetDigestSize()];
      H.DoFinal(hash, 0);
      return hash;
    }

    /// <summary>
    /// Calcola l'hash del round
    /// </summary>
    /// <param name="round"></param>
    /// <returns></returns>
    public static void Print(this byte[] bytes)
    {
      var sb = new StringBuilder("[ ");
      foreach (var b in bytes)
      {
        sb.Append(b + " ");
      }
      sb.Append("]");
      Console.WriteLine(sb.ToString());
    }
  }
}

