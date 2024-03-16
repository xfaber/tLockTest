using System;
using System.Collections.Generic;
using System.Linq;
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
  }
}
