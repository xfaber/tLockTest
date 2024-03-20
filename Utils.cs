using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static mcl.MCL;

namespace tLockTest
{
  public static class Utils
  {
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

    public static byte[] GetSHA256(byte[] aBytes)
    {
      var H = new Sha256Digest();
      H.BlockUpdate(aBytes, 0, aBytes.Length);
      var hash = new byte[H.GetDigestSize()];
      H.DoFinal(hash, 0);
      return hash;
    }

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

