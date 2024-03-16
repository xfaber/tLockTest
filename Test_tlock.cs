﻿using Org.BouncyCastle.Math;
using static mcl.MCL;

namespace tLockTest
{
  public static class Test_tlock
  {

    private static void GetRandomSigma(int round, out G2 pk, out G1 sigma)
    {
      //Test di una firma BLS
      Init(BLS12_381);
      ETHmode();

      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2(); //Zp
      g2.SetStr(g2Str, 16);

      //sceglie una chiave privata casuale
      var sk = new Fr();
      sk.SetByCSPRNG();

      //genera la chiave pubblica su G2 con la chiave privata casuale scelta 
      pk = new G2();
      pk.Mul(g2, sk);

      //firma il messaggio s = sk H(msg)
      var bi_round = new BigInteger(round.ToString(), 10);
      var bytes_Round = bi_round.ToByteArray();
      var h = new G1();
      h.HashAndMapTo(bytes_Round);
      sigma = new G1();
      sigma.Mul(h, sk);

      var e1 = new GT();
      e1.Pairing(sigma, g2);

      var e2 = new GT();
      e2.Pairing(h, pk);
    }

    public static void RunTest_CheckFirma()
    {
      //Test di una firma BLS
      Init(BLS12_381);
      ETHmode();

      //bls-unchained-g1-rfc9380
      var round = 5928395;
      var pkHexString = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
      var sigmaHexString = "a5d07c0071b4e386b3ae09206522253c68fefe8490ad59ecc44a7dd0d0745be91da5779e2247a82403fbc0cb9a34cb61";
      checkFirma(round, pkHexString, sigmaHexString);

      //bls-unchained-on-g1
      round = 11775741;
      pkHexString = "8f6e58c3dbc6d7e58e32baee6881fecc854161b4227c40b01ae7f0593cea964599648f91a0fa2d6b489a7fb0a552b959014007e05d0c069991be4d064bbe28275bd4c3a3cabf16c48f86f4566909dd6eb6d0e84fd6069c414562ca6abf5fdc13";
      sigmaHexString = "82036f6bcd6f626ba4526edb9918a296877579707f49a494723d865d27d42d84dee9cce84a37c21fe6d365ad9fae75db";
      checkFirma(round, pkHexString, sigmaHexString);

      //generate da MCL
      round = 5928395;
      pkHexString = "AE5462878CE369072BEC7690B59FC50AC6A082E4EE3116AFF0299E9BBFC0831783890366A3C1C181D1D0EB41826CB2611444E36D48ACC772AD345C73746DBD3BD807ACA3CAD993010D7CD0955B25A222D6245D84DF84D295FC7E310CEF974AD7";
      sigmaHexString = "A15FBA695765D9467C8F2CA46D57B9181822E305096A1ADFB0E4FF5F1964AD192F880201F99329580168E54A22596254";
      checkFirma(round, pkHexString, sigmaHexString);

      G2 pk;
      G1 sigma;
      round = LeagueOfEntropy.GetRound(DateTime.Now);
      GetRandomSigma(round, out pk, out sigma);
      pkHexString = pk.ToCompressedPoint();
      sigmaHexString = sigma.ToCompressedPoint();
      checkFirma(round, pkHexString, sigmaHexString);
    }

    public static void checkFirma(int round, string pkHexString, string sigmaHexString)
    {
      var pk = new G2();
      pk.Deserialize(Utils.FromHexStr(pkHexString));
      Console.WriteLine($"pkHexString:{pkHexString}");
      Console.WriteLine($"pk: {pk.ToCompressedPoint()}");
      Console.WriteLine($"pk isValid: {pk.IsValid()} ");
      Console.WriteLine($"pk isZero: {pk.IsZero()} ");

      var sigma = new G1();
      sigma.Deserialize(Utils.FromHexStr(sigmaHexString));
      Console.WriteLine($"sigmaHexString:{sigmaHexString}");
      Console.WriteLine($"sigma: {sigma.ToCompressedPoint()}");
      Console.WriteLine($"sigma isValid: {sigma.IsValid()} ");
      Console.WriteLine($"sigma isZero: {sigma.IsZero()} ");

      var chk = checkFirma(round, pk, sigma);
      Console.WriteLine($"=== CHECK SIGN: {chk} ===\n\n");
    }
    public static bool checkFirma(int round, G2 pk, G1 sigma)
    {
      Init(BLS12_381);
      ETHmode();

      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2();
      g2.SetStr(g2Str, 16);

      var bi_round = new BigInteger(round.ToString(), 10);
      var bytes_Round = bi_round.ToByteArray();
      var h = new G1();
      h.HashAndMapTo(bytes_Round);

      var e1 = new GT();
      e1.Pairing(sigma, g2);

      var e2 = new GT();
      e2.Pairing(h, pk);

      var retCheck = e1.Equals(e2);
      return retCheck;
    }
  }
}