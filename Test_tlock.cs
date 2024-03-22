using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls.Crypto;
using System.Security.Cryptography;
using static mcl.MCL;

namespace tLockTest
{
  public static class Test_tlock
  {

    private static void GetRandomSigma(ulong round, out G2 pk, out G1 sigma)
    {
      //Test di una firma BLS
      //Init(BLS12_381);
      //ETHmode();
      //G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
      //G2setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");

      //mclBn_setMapToMode(6); //MCL_MAP_TO_MODE_ETH2_LEGACY
      /*
        MCL_MAP_TO_MODE_HASH_TO_CURVE_07 = 5, // don't change this value!  // draft-irtf-cfrg-hash-to-curve-07
        MCL_MAP_TO_MODE_HASH_TO_CURVE = MCL_MAP_TO_MODE_HASH_TO_CURVE_07, // the latset version
	      MCL_MAP_TO_MODE_ETH2_LEGACY // backwards compatible version of MCL_MAP_TO_MODE_ETH2 with commit 730c50d4eaff1e0d685a92ac8c896e873749471b
       */

      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2(); //Zp
      g2.SetStr(g2Str, 16);

      //sceglie una chiave privata casuale
      var sk = new Fr();
      sk.SetByCSPRNG();
      Console.WriteLine($"sk: {sk.GetStr(16)}");

      //genera la chiave pubblica su G2 con la chiave privata casuale scelta 
      pk = new G2();
      pk.Mul(g2, sk);

      //firma il messaggio s = sk H(msg)
      var rbytes_le = BitConverter.GetBytes(round);   //--> little-endian
      var rbytes_be = rbytes_le.Reverse().ToArray();  //--> big-endian
      var rHash = CryptoUtils.GetSHA256(rbytes_be);
      var h = new G1();
      h.HashAndMapTo(rHash);

      sigma = new G1();
      sigma.Mul(h, sk);
    }

    public static void RunTest_CheckFirma()
    {
      //Test di una firma BLS
      Init(BLS12_381);
      ETHmode();
      
      //https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
      //https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/5928395
      Console.WriteLine("=== KEYS AND SIGNS FROM DRAND (SCHEMA: bls-unchained-g1-rfc9380) ===");
      ulong round = 5928395;
      var pkHexString = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
      var sigmaHexString = "a5d07c0071b4e386b3ae09206522253c68fefe8490ad59ecc44a7dd0d0745be91da5779e2247a82403fbc0cb9a34cb61";
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
      checkFirma(round, pkHexString, sigmaHexString);      

      
      //https://testnet-api.drand.cloudflare.com/f3827d772c155f95a9fda8901ddd59591a082df5ac6efe3a479ddb1f5eeb202c/info
      //https://testnet-api.drand.cloudflare.com/f3827d772c155f95a9fda8901ddd59591a082df5ac6efe3a479ddb1f5eeb202c/public/11775741
      Console.WriteLine("=== KEYS AND SIGNS FROM DRAND (SCHEMA: bls-unchained-on-g1) ===");
      round = 11775741;
      pkHexString = "8f6e58c3dbc6d7e58e32baee6881fecc854161b4227c40b01ae7f0593cea964599648f91a0fa2d6b489a7fb0a552b959014007e05d0c069991be4d064bbe28275bd4c3a3cabf16c48f86f4566909dd6eb6d0e84fd6069c414562ca6abf5fdc13";
      sigmaHexString = "82036f6bcd6f626ba4526edb9918a296877579707f49a494723d865d27d42d84dee9cce84a37c21fe6d365ad9fae75db";
      G1setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"); //su alcune chain drand viene usato erroneamente un DST sbagliato, refuso post switch G1<->G2
      checkFirma(round, pkHexString, sigmaHexString);

      Console.WriteLine("=== KEYS AND SIGNS FROM DRAND (SCHEMA: bls-unchained-g1-rfc9380) ===");
      round = 5358915;
      pkHexString = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
      sigmaHexString = "95f058cbd1294bc3fa28647dabded06d50b543643fb04e1cb2c5b6204daf20935782f7cae5fa7718cf87b4c43d108842";
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
      checkFirma(round, pkHexString, sigmaHexString);

      Console.WriteLine("=== KEYS AND SIGNS FROM KYBER LIB TEST ===");
      round = 1;
      pkHexString = "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e";
      sigmaHexString = "9544ddce2fdbe8688d6f5b4f98eed5d63eee3902e7e162050ac0f45905a55657714880adabe3c3096b92767d886567d0";
      G1setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"); //su alcune chain drand viene usato erroneamente un DST sbagliato, refuso post switch G1<->G2
      checkFirma(round, pkHexString, sigmaHexString);
      

      Console.WriteLine("=== keys and signs randomly generated by custom method ===");
      G2 pk;
      G1 sigma;
      round = 5936087; //LeagueOfEntropy.GetRound(DateTime.Now);
      G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
      GetRandomSigma(round, out pk, out sigma);
      pkHexString = pk.ToCompressedPoint();
      sigmaHexString = sigma.ToCompressedPoint();
      
      checkFirma(round, pkHexString, sigmaHexString);
    }


    public static void checkFirma(ulong round, string pkHexString, string sigmaHexString)
    {
      //Init(BLS12_381);
      //ETHmode();
      //G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
      //G2setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");

      Console.WriteLine($"round: {round}");
      var pk = new G2();
      pk.Deserialize(CryptoUtils.FromHexStr(pkHexString));
      Console.WriteLine($"pkHexString:{pkHexString}");
      Console.WriteLine($"pk: {pk.ToCompressedPoint()}");
      Console.WriteLine($"pk isValid: {pk.IsValid()} ");
      Console.WriteLine($"pk isZero: {pk.IsZero()} ");

      var sigma = new G1();
      sigma.Deserialize(CryptoUtils.FromHexStr(sigmaHexString));
      Console.WriteLine($"sigmaHexString:{sigmaHexString}");
      Console.WriteLine($"sigma: {sigma.ToCompressedPoint()}");
      Console.WriteLine($"sigma isValid: {sigma.IsValid()} ");
      Console.WriteLine($"sigma isZero: {sigma.IsZero()} ");

      var chk = checkFirma(round, pk, sigma);
      Console.WriteLine($"=== CHECK SIGN: {chk} ===\n\n");
    }
    public static bool checkFirma(ulong round, G2 pk, G1 sigma)
    {
      //Init(BLS12_381);
      //ETHmode();
      //G1setDst("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_");
      //G2setDst("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");

      var g2Str = "1 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
      var g2 = new G2();
      g2.SetStr(g2Str, 16);
      
      var rbytes_le = BitConverter.GetBytes(round);   //--> little-endian
      var rbytes_be = rbytes_le.Reverse().ToArray();  //--> big-endian
      var rHash = CryptoUtils.GetSHA256(rbytes_be);
      var h = new G1();
      h.HashAndMapTo(rHash);

      
      var e1 = new GT();
      e1.Pairing(sigma, g2);
      var e2 = new GT();
      e2.Pairing(h, pk);
      var retCheck = e1.Equals(e2);
      return retCheck;
      
      /*
      var e1 = new GT();
      var e2 = new GT();
      e1.MillerLoop(h, pk);
      e2.MillerLoop(sigma, g2);
      e1.Inv(e1);
      e1.Mul(e1, e2);
      e1.FinalExp(e1);
      return e1.IsOne();
      */
    }

    public static void checkFirmaOnG2(ulong round, string pkHexString, string sigmaHexString)
    {
      //Init(BLS12_381);
      //ETHmode();

      Console.WriteLine($"round: {round}");
      var pk = new G1();
      pk.Deserialize(CryptoUtils.FromHexStr(pkHexString));
      Console.WriteLine($"pkHexString:{pkHexString}");
      Console.WriteLine($"pk: {pk.ToCompressedPoint()}");
      Console.WriteLine($"pk isValid: {pk.IsValid()} ");
      Console.WriteLine($"pk isZero: {pk.IsZero()} ");

      var sigma = new G2();
      sigma.Deserialize(CryptoUtils.FromHexStr(sigmaHexString));
      Console.WriteLine($"sigmaHexString:{sigmaHexString}");
      Console.WriteLine($"sigma: {sigma.ToCompressedPoint()}");
      Console.WriteLine($"sigma isValid: {sigma.IsValid()} ");
      Console.WriteLine($"sigma isZero: {sigma.IsZero()} ");

      var chk = checkFirmaOnG2(round, pk, sigma);
      Console.WriteLine($"=== CHECK SIGN: {chk} ===\n\n");
    }
    public static bool checkFirmaOnG2(ulong round, G1 pk, G2 sigma)
    {
      //Init(BLS12_381);
      //ETHmode();

      var g1Str = "1 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
      var g1 = new G1();
      g1.SetStr(g1Str, 16);

      var rbytes_le = BitConverter.GetBytes(round);   //--> little-endian
      var rbytes_be = rbytes_le.Reverse().ToArray();  //--> big-endian
      var rHash = CryptoUtils.GetSHA256(rbytes_be);
      var h = new G2();
      h.HashAndMapTo(rHash);

      var e1 = new GT();
      e1.Pairing(g1, sigma);

      var e2 = new GT();
      e2.Pairing(pk, h);

      var retCheck = e1.Equals(e2);
      return retCheck;
    }
  }
}
