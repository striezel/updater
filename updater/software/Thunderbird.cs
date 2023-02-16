/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.8.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "0a12414eddad5157f9ca24bdfac8fcad206ddff032923aec513e56c4fbd6dd264c5110cd968dee780e5e560d5e70fa9b7c9ef2a9640df5d02c33c7b17b412b2f" },
                { "ar", "7f960e38657a35c3d6e61936ed405745f93c3ff7f4fb9ec3b19fcc47fc7448ff7f0da3e0f101ffc9004efbbf5f1940d1438337af27a41c6b6947b2de7e87d30f" },
                { "ast", "c085a1539a9de039e91f4fe158f5fd00bf32f4eda7f577a44a4f16ca39a7ab811909f8b1be32105734b3b14d75cdab4d9b9ab74d9af3b873bb12fc41db0cfe12" },
                { "be", "c96e128a45fb34d59404019e0ed2345e8dd8f7a61c33945c3eb7944963422878e209c9ca3707148060cf16672ba002d5c71334236d3d23cf5dfe03fa71d3a2a0" },
                { "bg", "87ecdcbc08742a5aa69979d16b249a27b510cecb15ef29cebbb32c9e635627c23c48eb70a07fecbe97df3f85b5341119e5929563c8bc5eadea1d843e45d96b5c" },
                { "br", "ddbe6035a72a9f922abbe9a2d25598712d469253366d0cb0e765a550032e1904c9136e42fdaaa3ee06759d14af54e68e79f052a1e8d6afe6ec6d0b338b182ed9" },
                { "ca", "593b030dd55c329efe4e06554b21a9194c51e95c095d8dd43149e892abba8f75d566c7efdf41987e74bef6ce8503d96920ad36422f31a52202dbac341730210a" },
                { "cak", "dd0543e8d7f20dc2fe6384afaf4e185e726d4c3a31aa3164eb2828aa31fc6e99ffacdf64a9e5dd3b966530fec3241d9ac0662595d1c6e91ce672c5ec9557e4f8" },
                { "cs", "7c9b3aa19592a7614ab7a4fec4d1e0ffb5d6234ced206babf886793bad27c386e011b758848ebb890488160f6cf4e05070cc2d41f5fa365876e4d05368a05cb5" },
                { "cy", "952be1b492500bddc87075367c16f4093dee64917519f4b9847614625a88fed2a79b87543eb814d842359026188222e731d3479e37406768fcfdd0c71dba392f" },
                { "da", "fc743bad28371c0fddab19641da60220ed0e079f28ee510f27dbf61a2b1b9f9e51c88d294c5a223432e857f67fcc2d62383415ebfa26790cad7fedf8bd00bc27" },
                { "de", "198a1418dc51cd6b6d7c11dcea01b622a10a6ffa3a7c13a3940aec77e7c13764f5162f90e6e25870b211111f7433fda98c34e6b8d8b4cf116eeb5b5ad7d10304" },
                { "dsb", "381b2eb1750fa8ce254a24070e1cd1be864b56ee3762c787b693c3f8280edaed71315b7afd3dfbddcc2e10752cb8dfee0b22572ca2d354a737531719de46aef3" },
                { "el", "04a9d20f38d5d39fc3b7a00a120ee86e92afafa9f16098260f6fe8aeb781522e0b6e37962c1bd97d173bb0b2e088b639dc9afadf09f166b67b8fb4a2473be527" },
                { "en-CA", "10577ea8b02eeb39dfb2179343a078ecad4d1c679b69c3e77000655f4ce30bb0490f525c1a2465013a411f19eed018c1cef6d1cfca6af86c35c40205b92d8646" },
                { "en-GB", "9e67a0da7dc754589f5d344eaf3f66aa96f8ce2ffde717c3d4ef12a2eb612a9dcad2aaac3e7db69203a6829b89fbddfaf75becf595e7605d189eb747de6349cf" },
                { "en-US", "f70a4cd3ca96cfc1e3ec88247b3e27378b33e329159f3ef5e50836853c3b1324cb189ba19666009edaa9082602c05592401dceaf4b97fcbfceb8da588c17bde6" },
                { "es-AR", "fa4ee640372b0f57fe395bab5112433bcd27b13733f9a243fb3fb0a3d1e1fb828201478fd362f177c520e281438c2aebb70310e87948f0d2a87616411c0b0319" },
                { "es-ES", "3e85fce5f3e80b3e408a97d1d406bdcd92985934780c1938505d090d9a9f782cc663b81d611c50385cf94c8b585ebf9be4825a2ad087985f305f80ac9f9d9f04" },
                { "es-MX", "b2f08c28a32502885b49ae1e6cbbe988d5337c4092b604565fd9127144266c95b57e985051c8720b4fe3c8380ee61bf0ba1da86b798f7151a0345ab85b4c743d" },
                { "et", "dabdacdb75fb36d6be9be34050568be6abcd0408e0304c437887ab3539b70670bbabc5b3be2a60fba69d8f73a97180369aba40e9b574e49591324aa8259076eb" },
                { "eu", "521869028ec2b7b23c480b5bc9a7e37ecfc4ad2c0049bfac5424f123dd50a22983e5957786943d54b6581fd9ba1cb8b98a9d14c928aaa3f6045dff1299a2139b" },
                { "fi", "d3cc42aa1d1d3d7993afac6bc777de499cec7dd173296307adf6cac6246c093b33450def8033e87bdaa1b5352c01da14e886657c9d23f3050b22eada5597fc51" },
                { "fr", "56d374aa3b35a7b9aa91be36fe7d9f451b7feb10b7fa030d083ce645db3f54011c5a4605759dcfeb097e6c729736ebfc77daad40ded7a6586046e5e21a679f3a" },
                { "fy-NL", "7aa4911574aec9c9595d2e3bb59a6bebb59db2430f546f6a02a47e9216bfc30fceccca6c9c0d5b13fea9f82d947129012fe2419430dbcc2140f563b9d7f8eeb6" },
                { "ga-IE", "f1caf3dfdd4f6ea8a7488a8e78c25b1dced1e888df070eeb0083ec10eb02011ed651228aefe2247b9a9e081b4ce66a7c00a5485bed87f94cbe655219592d15a1" },
                { "gd", "75ca05979e2a7e0f0049a0e3e21c21c5fa71b145b21fa90847c18afe44f8e7e7293ade52d90c880e8174e3d3fddcb1475d14802f8e2687a4b2a76e5f96c3c160" },
                { "gl", "7cf67c63c4c90b0e17d4a0d46fa621044e6c8918eee7bafdeb21bd3c0873d40fe57d3330240a034386c9f014a26001b672de4d90e9f5e337aa7fd699575c8ffa" },
                { "he", "112f1ea85a9c0913008298f9856d60c582a9ac2df63c8634b38271f838c660236881897c30e27e03564f8247e0b546821a05bd5db82aa57b15a1c15d2af6ebc2" },
                { "hr", "72a086a926d714853d9f384d072f65132ce3af9d3b61fdff559fdce3bf2cd9c3232bdc3dc3efb5d28552d6f21bfb7a85c145f9a8d5a9e99e1f626e0178c3ec31" },
                { "hsb", "f516e341ce434bfb889281bedcdf84be3e436f9f9f314838387da3189c3e38cfd2d9b5520a54be7e05efe94855b1e625950b02233e5a9c1652a9652957c942b6" },
                { "hu", "7b4af4c285cb7573151de72508663132676d590165d2303b2f744991fe1b78d9aa6751995f3de2a9d968b831b6cdcd92f89d5d6f5be4afd7bb009ff5ff46fa9b" },
                { "hy-AM", "e4f450387d7965cd1542c262021619c034e93b85127f27e6906c473534c3b602fab154283735f786d427421d82feada6fe559947f05a72b4bfddbcc23b51147a" },
                { "id", "a6b042e77e579e893a418c969a5defe542fc70c3da3b7e8d75dece5d71a7256dbe1345dbbccafa9bcc3b3781d6d02b12a31ce2c4265a672f23e0a06b867159b9" },
                { "is", "6d60ab1f72056bd9e34d08415cf65bb8c06dc3d143a70d45393f7bf8997710f68a11a1e0e526b5bf115db22502258eec0a4ec01a661c4b4376893ce627b433c5" },
                { "it", "7116083419a7f5f1f5ee47a0dce7d0bb11a439a4dfd71d740426aea10c4e82ec34b0ffba44cfeccd3b09b4d8dbb33c97b6c9d83314a952894c2fa7d88ea8d50b" },
                { "ja", "c2d35af03fc2dceff189bb7a50f5f651e1f0b2954cf3f0654de0912e98c0092a3f4524ed341de4dce7aeba1aacd1a36fed13c7e1c131d6608b838cbc8246d67e" },
                { "ka", "d7e9d7f4785798916860276644a42f00edffc692984c6b2ad25e8e64fd00e0cb461adb5aa14d05f3d82a9ec3fc9a5ded0191c52af8bb60e204d26719ae96a342" },
                { "kab", "30150075b155a4fd9d629fba3a4549a4a28bef956e94f9016e0296ea94488b3de194f9edb95beb6bef80c6070db0a996ce2440804f52d46dac461f2b13969e9a" },
                { "kk", "4f977621382db3ac8becd969488dce35c8af94b30dce57ddb8b992759d2f6e9c90c54c29ad8b147b81e0ef983efcca224f7abe2ad5c3f5b6bfd5e5e870a5e8e9" },
                { "ko", "10e4c3c9d2a6dbe665ee706890913d366fdef9d547394a0733571e663d54636a386ffefb04628022094686c9c3a0c0deb98d2d921791b90594fa0e7bfb6e90d8" },
                { "lt", "c3f85bb8090eae2ed3d972975508d32092a1ddf7ce408eff957e4ffdbb8caa88d57cc2ff57a194f8dbfeb12b0b4d65295bbf90e3658bd7562a978015767d8354" },
                { "lv", "9e221b7a92ad1aa2df52a3498befabaf6976ffe906a12454aa08caf8034ac996a06497d026b8091f89b6756e35cc4e691957ffdee82b1fe623adf2897a1953d6" },
                { "ms", "d188d20b3f69539990182b524f234cb5224130e1564c60bf3df575764819ac9abad471c4476e632c337835825fb5c7e768cf7c5203cb62de273a55f3fc5c2536" },
                { "nb-NO", "83dc11ed603b15060ab6b9ed644b1fc6bf923a1c3979ccaf5525a74ae13b88ccae44735b626454dcd5d5d71bbaa4281d4f28c807d686baff2bff66ac4038fd98" },
                { "nl", "1ca16138159cbad29c6d6fc8cf60177997086355c90a0eecdfff5a48bdd3a6d2c4c5042ef9f5e0c265237af5c571842ddcf1036399e620e53c8947b681841b1e" },
                { "nn-NO", "568cea602f249f9f25f084e610e8fead5b8fff01819e989c220e56e81776f7d08b7bcf1847e72eb110892d317e3d8227d5443322fd90c8c325ec7385111738be" },
                { "pa-IN", "1070b87dad4ee0d07c1be29fce776a63ebced8347c192ed2a2df5f26f32d0b5d43fb94f4b82dbfabe011f3ea37121ca7d9e6404749a365c10db942a8a6fc24dc" },
                { "pl", "13fe6f92527fd65fa97a4f25e65dea82fecfdd04e17cb5d3845c88c14dea5182c594ebbc8d4bfc8bfce45144b5c38e8b152c3691a6bc6203330b60af4a3ee728" },
                { "pt-BR", "9ce7a9466fab60e1a30b516d8a2ecf05f90ee701d563c78177d9aadbb20f077e16bbf3baeafa78295b79e8606f47c74cd349198eb37553301077bafed7f8b361" },
                { "pt-PT", "6a2bc187901b423b9b9663c53436b8a5a0c240643e5ab29dd987d472abd5dce8f085b3376e955835166d27b11b57e8a8e06012598564e55b1b350200bd7ab503" },
                { "rm", "bffa02f01bd6900f8d17041915d4011265fb2cd27ec02dd7e447a0817e3ab94a9f9d5109d5c2e8327cea0abada0cd16c04d8bb893ed16acd2632da7bc85afc6c" },
                { "ro", "ca1c912920a330f9e3d82e1797f28f536071625343d2d875787d17fdf602428e6253813d58408ec04607a54567644f2dda28750a56cbb22e6e86ed721fd599db" },
                { "ru", "0de97ab795e93f7b6b46cb1973896b637fcf8f1052b31db121ae205f807e02e4e7959ba7a0faeb13067802c9b63e847d80edda996ae8245e21103db72db81039" },
                { "sk", "6515e358deeb7866fe225614e6e864b31db802cca2dc9a704dfdad6efaa3a473a9d5768410c62fed249f95cc09208a5482b5dcb1b831b8e8a5e9b662d72492b9" },
                { "sl", "575a58c85fe7b68af85985efe9e228f6f9636f629e54fd25952e49857d3a07bf919d0b8e7aba3f6610dece4c88ba0ee374876b31f388ef4529e68a11dd0c2e7a" },
                { "sq", "792291f4930e8821463e388d247fbf6eee4c1f77b68172545eee65bbc66994e317b5a42246bb5fcc8971e54ce1cfe7926aab204979e4a4eafe3a6579986d31ff" },
                { "sr", "66b01209e2d2c8f9ba760eba6e5ccbcc4c012512aa62d4488481ad4ada8b31897cff5bba8013aed9805f707a0e3b2b70e24ba6b6602119bf1ae8d63f55ed6c3d" },
                { "sv-SE", "3468f340398aa6aa10fe09654b1c814243193cb6d0e2d484e166ffe8e1309ed28cdd1118d32e686c96b78ec9993f52ccb05d9401468088ebe93146fd3b42eb1c" },
                { "th", "2d2942526b2839e2c2bf7d70158cf1bf1a133667645ac9620fd5eb5204df7c68e977367b4473a04d541d992b41965d2700622b8b41ca167d9eb92cf21b7e841f" },
                { "tr", "269ef5265ad7e18663a0e6e7a4c2250b2a1ba740a0869de31872e58a59692ef5396ea1026637f79fa67805e1b4c25477aea0ed75dd95c114450bcfaa84596d94" },
                { "uk", "71bd2c3c10c374cbd30f90063c847f19bc1ef6015923b2d6eb9137083a188336a9f2eeb86e7eb177de91a971b164d29759c9fc69813e9c45a5dcb1f6b517b9df" },
                { "uz", "3a4f482c3de8aed2de9a8039cd1b46048e85337365a321784574da52bc7b314f15b05b2adab8f004f032924e57c9c65ca333c46af3cafb1c371951b7471929e4" },
                { "vi", "8498d035b59f48eeff943d23a1bd695e2b493bffd544e374dea9c702e8943359dac7f16e7d25f0723991043dc4ca7ae9b1d3c16aec175c66159fba54d1a7962f" },
                { "zh-CN", "b9fff5215dac915a8a492179e04be54a6638decb0b66029a37fbe71d852d22ed6854f449012b0f873888f8b1a6fe1e7f9e078bd86c9b80c0492147653f7e9b16" },
                { "zh-TW", "6ec0e7fdfa9686fb123a0bdbe4365c03a7ba6760aed7c4f2461bc94cc2cdc3077d9b7d474d0a2b369524cabafa67ab08be59b1d3f9a23db14b466cf6b8cebc05" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.8.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "0bf4fe9ede2315f347ee561f19e25912acac6129349049e4a66b78c843fb35c35c06e4f9ec44901052194ef54bfb76ad16317d0b0e96963b7fc409d152ca2684" },
                { "ar", "06b5b24c0bd9e60ddfb72efb43dd21b754cddd7f945ff81f243e8b3d59c729977fadf6b1ed0257a16cb1b9ea974a78af8badd0ffca0be238852d3bc3184a5420" },
                { "ast", "0ae1fe723206712877ac01edb2c4e030c0f01a2a8c12122a954a25afb770b0e9120361b261c575101d515ae96c184cc66e5cbc3059e5e82a2154906c9c93eec5" },
                { "be", "f171e0a6a93bed99f14ea8311fdfe7233b8bedc2b135864cf57398c0264077c5199967b96b5cdabadccc815e5d9e28617874565a4adbdb1d5e47129d95246683" },
                { "bg", "6c528e65dc7e630765f70c2d50af24e372b790dc29c92a056c374172baf427e147f601b36c1052e793df9f38080525404e412c1e96bfd77a185191a6ee44e7fa" },
                { "br", "4048def5870d32281fa4bba8998dffe2dd414663d479f3385156ba58af7d30b7ea5b9976038ad44f46f481219f6a90b8ead134efce5ef3f12e955fe24c24795e" },
                { "ca", "3018d82f681faabf18535937dfed6a7bf863e3308a44c3251d1babf2bec461e719b1d54f1811722944de8f7b87e243c2301e8aff35306b017d2f9baf60ebbd5b" },
                { "cak", "742608b6e9ea68b144ea72cab57d3aa61c67a89202ba13fbca36cfc1a1e9f3290fb4f1ba84f4fdc62858afec4c5c1dd703e31ca4f22fbab83f841931e6730608" },
                { "cs", "a8d98a8089d3d8a2abaa81a5a841a1a5e6934f2fd176e119875d35f0e6038544b6cbf742cb354559abc6edcdcfac97533723c35349453cec66600fd68b5a5194" },
                { "cy", "e1d8d1498464ce6ce9056e9e4e097d6958c6d292b36b540b3f089a461391bb3f3a556bb2c017165df1f4a1ae1fa9d76731c86ca7962ecff219f6e2530ed51561" },
                { "da", "84512518e9c71d663645e318aefeac6aaa2d9d591451d44a821e936cc7b84cbf14cbdbfdbc36aad8b1def1b46194c725752330ff91beb208a3a3e803ef829c30" },
                { "de", "e09378f8676236b5b4ba010c003a23206ed9949611f47ba2d25679d83ce741d0e6293b1ee23066f5791e18befb3e8e19c823b479bc8b92e0475fbc0e3842c826" },
                { "dsb", "65fd407b4f094e0ec1afb25a14b8d25176b79f533b70b0f681c29a6c502446dc30dcb088e63d102da4e261246eaa7df73d55ddf932c255c8526684c4c4d703a5" },
                { "el", "412085b4a9f43527d67be4024cd0244f98ef9404df4b3685308b661f2eba425e658c1bf972163429fd5f0ede5c19fb1a48a112320444b244cf5b4b1acc9e1f7f" },
                { "en-CA", "89433dfcb5522e2ea78c88d2da71299f3f6a91b522228265b3c80be00d56865fe14646b849c9e7d79d746725de711a1aa4da8c9f3f038d7db7979b491cac79fa" },
                { "en-GB", "86729030d48a90f5aa20c0ffb8bb6b7524a69a822e878485e1fcc19e6eedf6b6994e8be00d598bef87e220a496ec1825384de4aa550a2c3527090bcf886fd057" },
                { "en-US", "c717dc1b5e3a7dcfe755af5d7bf8e004929e3887502d6999f6a5f51d668755da58ac14b640cb9f36730ec437ab88b6a2f5c8d6cd11b14120beb79049f96ad86b" },
                { "es-AR", "88aa3b2cf42ef88afb53172a36d44e7ad166a6bef34871541428a49c3099c04aa9acbcf1690223b2ebb9334b4af0a83902919cd97b1830e92ccedfe57e83f323" },
                { "es-ES", "91d398bda283eb16efefa7174a31bfe4d35c5d7804d1f729f4575fcf6ba0dffdaf9d52b01b8937aeb24fc9c45d9f77b321dfb5d707ff3f936cf0a6ff10e0374a" },
                { "es-MX", "ca40e1a80a77bc10d5d61607c02ac44945a71872e8ad42937c451fd7e988624722e9e1b44f8a720b199d6848eef5e3df5d5f3c3b42ab93b6bb2ad2d954e49239" },
                { "et", "42aebf47d4698e29f5a3e1e8eccfc379d859ce731bf0cbadccd9ef8fa4c16b71af02120f1c6b1fe430257b4cfaabd5910fa271ab5ddbbc51496b200d6dcbb70e" },
                { "eu", "27740d7aa80ba4b2d259d9d6394caaeada93948465200f4a0579caaa70fe8a076cf959c064eedc04a0f67b67519fbc5a7ccb00f5feedbbf5a708d17b4d0884b8" },
                { "fi", "c8739432a41ce2271f4d56d806090f1a6428fcfd92ee1252c5ab2a91ef0241fde48becdc337ca2d26bdac3b50b630faa1e5452a5f99ab4d5ad884c8609ce14eb" },
                { "fr", "cde90a1270d6b54575ec56bd91fcdf50d4d0bc071ac3444582cc8b28e629d9d8158bb472b2217a7e8b1d673961c0bd7555bdd41c2952d479dd7e771699fd4daa" },
                { "fy-NL", "6cb6893d170c0a719169c0cafd617daec9d2db86619bb597ddd13ab3af0ad66b74e553934c55d67f69adc1f7fa076e846e56a7cd10eb1398f0b42bb5c9c7926d" },
                { "ga-IE", "b4ffedc3643f75d271363dcd10ccbff2068a4f7fd1f08b5bd9891c7355dfd7a04ab4c248ebc5d3948a4356a3a7eea26c47aadd69df5a72bd342133154fbc6ef6" },
                { "gd", "3a8647a65ba6112e066fe5a0fed1574dfc2bbf9172b6300fab9146815af1a20b6f512b06e4f7c8fb8442cadc285b686b592f315b2d334cc85533487bdc454cc1" },
                { "gl", "466f37132b138c214eb1652808b5b9c1ef94c1de1b59088e1b2c0deccd314a694fa37ac14aeea5ce8e0b2a1d02fddd5b100a42cabda90ac94a3875422a00f863" },
                { "he", "f69bb9bf92be51d2b588ea3f0f8c9d7be0be71419a73f96c01fc108d275eaf1f2e72fe62f1f0647fd449244763b2983a3a3cc3f5d484e202d9720a2fb65b0efc" },
                { "hr", "17fe0231b6a365574019b59e9791f6ce79657d4cd11434f63421924aec9a3942d7204cde1d8998b801e4738972d2b0e0753192b474deba4b830fa5938bbb5555" },
                { "hsb", "cf8252e5700cfa9d97dc261fb2e392dd83a4a72c76840fd43c25247957d9eebe72be4be44d32dbbce9633408ab9621590d00b3ab684952bc132deb8a826d6a9d" },
                { "hu", "2945bb4efed2dbfa705875d0eb272a2ec9913053bab042ad280674e35cf057036c772d330e9fcde7600127bb5e7ac18cbcb956b1d0dc3bc44581ebfcdfa69b68" },
                { "hy-AM", "3b7b23664f04e792b4c0a00843546c288ad582bac42a2129035ea665f9e93bd5ca6e587e4afef5901b059bc3d701e1ea47f5cfa9ce87a9d428f1092e35787f12" },
                { "id", "00043062246ec5420519579b6113e5bc09ee798e678d417e8d15e560c9d7b8a2566f21f0c5d9a7a08cbe81e98d781002c6625850fd3fc87edbc2a5414582ccf1" },
                { "is", "32b5acc0a7007917d38b15c26756e506514da4f35153ece6ef0604320deaa2d5dc89bb28b666aa5e2a8de7d357202df6fbe74c8bad0692a6accb8faea7226b2e" },
                { "it", "fb55fc6959d8f4ff23156319f31fa85eca5fdf1b4fe0dc3ffb33205f097a86fabafe98b6fa46e5fea9d532886f1aaee231b5c5960d811fbad1862c524f9cc5d5" },
                { "ja", "15d64f20c58d1d4037cc21287ff77489c2ce1903582ab044e041d0dc0d5ba8611395ea4323933a0e9370c947328c0f7b78c5607446b8337d6c12001e8680d918" },
                { "ka", "6f833dd542984a4be8843773cfb24e6322ffbc38faa1bdc4d8d42c06c7e5baaaefc65a3efc779ec23af2e380383a0b1d222b29f106fc815139fc0835c18c1ade" },
                { "kab", "d4f0c3b3508daef878d5620b18e57e83b3a4e88ad83b8e019a18ad88f9c5b669c1915112e95685f7fe73c54bba32a5e522759a66f1b75e45c413b4930f502f74" },
                { "kk", "4ee6c7b1ac467bdd75c04f2f29c9fddd3e41425f0747f860e33eb319d5ddacb00d195c73595bd5a2c180640299df5a952cc199e49b918cf19f79bbb0b03b5870" },
                { "ko", "81b7110c6be34917a5f63977e500c7c73d0ed08d4fc87abb7672476ce87d28e8c7322b7e9c1074a86fe579c1a9df2ba05755945a73b9c62334ad2a84f0d027e6" },
                { "lt", "922d7358bb8275dbd071729d5533e37501346f7fba59f821dee79a2a3cc0e9e72c2e0889f673c4dcd3557f7ef99964325e9e63cd17b7133cd67286ef64ec6ac0" },
                { "lv", "d8af49c5cbf774c272dfde6e35e9d8692a3fa36d683e1935b07446cbb203a5999eb446d7be68b7b70e56e4f5d979907d68047a1b0a8484fae389c4dd5695dcf8" },
                { "ms", "bb578e8d7b47db800853eb7c3c16198d8191e7ea046d65803e7a4e194b2aa725d9bb725201ae97a4295425ec53b77422bda8e83e5ba7edcb547440a69f1e534f" },
                { "nb-NO", "53c1a6d3e6087a88cf764e6737e4137f861dcaff953e3bd23de63c1274c7fd9ce7465fd94629f8c8895a0f813032becbf6b6be43e86d9413bc507c2c5085b8bf" },
                { "nl", "c5437b9a8b1e022ecf839ee49aa20e51e54328cfaeba7a2bea5024888557d84ddb2f9cbae62e89cdcaccdb304b0f04dd5f1092edcd1139ed693248ad004cd14b" },
                { "nn-NO", "8d05af97c34097ff928298e4745daea5f03a23d4674841676af1fd0b916648df26e1b30745e68784f795f1a97766290745f4c0d1624900e54676e11d01682a11" },
                { "pa-IN", "306217b90911808bc459705a2a8e4afa3e01b3cee4a0443310ec62124559afce3bd1a336d433d89ab9d7212a96640d102ad19244a3aa468f057f990e3f6b1efd" },
                { "pl", "5bfadd8322fb6bf184ef9fb82004e982b99de4fe1b0380f7a77f018818109458917b1dddb75492b5d5479326992a08c8b05d82ed3e4dee6d4a2d113ef4d1132d" },
                { "pt-BR", "3197fd48e484b25125f163f2d051b5ea708a339a24d9a7d2afca6538fb7a02b1b8dc9d696fc5e2cd925f82ad92450fcf82dc25eab2b6f8d1329101bb07f15e4b" },
                { "pt-PT", "2c16fc93074761f7478a563aed753ee1fb01a9325c95471b52c4b7fb646f413e263de43639ffbe5f3f8407a062fb26a8828c62fcd4045d0850e88b6a29ac2798" },
                { "rm", "5d405b96a9384a93f1aae13eef4ccce9dc29f04444f11a4f92fdd3ae39d428a3c50f30b78149787c92bc462685a76eb51e2f1d55332cbc8781bfd9404ee1cc60" },
                { "ro", "d56d92563dcfce5b15fd903827a6a15348817a610b6ad3d49aeb0f044ff4a462bb7ddcccc9a3eab2b5d5c53634e72132b984c9d44f07c08a1de87cd6e8f7b2c4" },
                { "ru", "5766d31e8273bf39d17bd08f0e962aca3b197c0d4a8bae766ee020443962ef174ea420150c2f44aed687fb3dc7c95cbda89a129a339e74fdfed0f8c24eb4b3de" },
                { "sk", "78858d2ebe6216cdbcc88b48252af0cf41ef3dcae2c51cc0ba06201effff77f868bf4f7dee2e631df76aa76a6fabf0deed019c0fc066ecb4149b9a251bbe46c6" },
                { "sl", "153288cc9aa4f58247d016c3750694a8e0160c64a0f1f9ff09dee9b599976fbceee68e274a4cc2b4ebcf5c5edbcad528d4c566e28b638d5a8809da1a48ac976b" },
                { "sq", "5f1dc9a4a21e4fb10790a4e2dde5eda2925151f550a5187e999f7b6fde237461bca4156f1c028d1df5ad315ea1e60cf2d4603ced8fb72b9cc376daf34a3ee930" },
                { "sr", "c57813a877ae1b0df206f4bb1fc458a5387697412df46cac8dd5b5a120e20ce43567c53ea1dd0907c97afc6977e3d3db163751d95b7e57e5e46256a84484d61f" },
                { "sv-SE", "024e7128df1027dfe30b3d87b4563ad4eb77d33523493b97e4717dd1ebd94ddfb12412d7a8c54909c2d0df576a91312ef07314414dbc98de6e031b88919e2034" },
                { "th", "8c7015b8dd177e93db59c45ba32b24e6fff1ceab9845deda13243982c720be12b405fd1bfc54d51f03e29b5abee47fbb1b9c98f6eddc1c341b2417bda1f63e57" },
                { "tr", "fdaa06bb53b98a2972226e55bf1577795730277924a841e3e47a0340acd54f03656e6506b97122f6c8b149f89bb3a347b37e2f60533d81893dc4f4779d8f85ee" },
                { "uk", "ad4b2e5917f17da9004b35bc2a6347853624c73ce2e76eed047bfd50cb4567ce7c66ca13f11dff02236d3818e4c902c37888bfe0bd9c89d9fdac4f4df6a35842" },
                { "uz", "a85b89634f223e4f3503892f6bf5cf5f9cf01a6b224683c3ab80d66a8dba57eae26cf396aabb7b0d980a3f0b28e35d8dc737b5c170181e3db832487fa4d248ea" },
                { "vi", "8c28f385b179f559260aa00558f6e20e874fb8311902a37a8647b6cf98865e9cf9f3db1fd20f1bb2bbfaa71c6c37a9ff7ce54384e1c33a696880f86353b414f4" },
                { "zh-CN", "899bd7e2da5be6573ce440c37c803c110529774220beb6fc21e6ae4faaf5457b9e9f11db936aa71ccc5f8fc624bbf6e985458596a843ee08ff221a09016407d9" },
                { "zh-TW", "4b99e84278a22d94a79815b6ac0354d2a59254af4eaf46d45359346b68ed54a7255cf81b4e5ef0c57cf7e626614878fb6673d12734a4f29241c3f11370172c1d" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            const string version = "102.8.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
