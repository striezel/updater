/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);



        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/55.0.2/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "00852f69dca356ab0f758da203993a6e49b55e7941f072c469d50a3b8767b34e993e54a3f0b2e3903b96ad9d64fab188e58a445a43769d13e2a0ae1df25d11cd");
            result.Add("af", "9a5cb4263323800ac5b579eebccfb4435ead0b5770604b8ef1138fa4220e47d05f5fbbc5cb79e091c4fd514ca01f1617d31a35e5d221b061de0506403cbe29f2");
            result.Add("an", "eda36d366addafa6344ae11bde4387d9248dd2088c08affcfb341eff81eaf19f19b4af5140a51c72a7793c8c7df600154e107b33dc64c172af4008f45700d610");
            result.Add("ar", "c8a2526f03293bf141b2962341455a0b86813711c6e05dd61ef22ef67367e0b4b318b628e4db378515d3aa17d3375d883bc1ce38ba7f971349153edbfb2eea62");
            result.Add("as", "1bf878eda641183c374563655f0737da0b9603123e9024994715f3282d6183845df6fa68a9fb885a20eed5598ddb56b297750ec39b3363d013acae78dc23be8e");
            result.Add("ast", "fdcdaddf907697c5c8747cb30cf0f233f3802e5d83cac49323d010ea9ad5e2779a47b75d1c725bdc2e805015feee6b7797d9ce777b124a9f5bfadeb93ae9a2e4");
            result.Add("az", "09454a66108cf9e2094b575e39485a10650037e6ea7845ecf5fbbba01fad6ed3550f104e8c11b6ac8cd701d7542670cc9d4a03ef7115b05aa30f38f846ecf8fd");
            result.Add("be", "06fc0c40705d1fa9aa12228a7fdf1059abcd265f6ac316ba68da071309bb32df6951110b42d178c3521b9d17b663f0c789292bafc0b02addb0236d6d128c66c2");
            result.Add("bg", "dc9720f6b5612eee81395d05fc22a9cd92cea1e69f6607d7c3a494eab54a70668fd7e1e279eef49469e067b3fb310741535456f766c914d9c7a97e545de85c78");
            result.Add("bn-BD", "be9dcce1f568351dd8753c873aaea2814be0d7319bfe17d5f37c0974d334050ac251ae464d2aab56f0649ceca48aff9da249758cf31c8538c8eb36054e9bd88d");
            result.Add("bn-IN", "c7356367363b368cd54a252cad27e74da2d738f01508028090f0ea1fd2a5093320504ea85cd518305eeb56842d90411b8b19673a62e24abd101cfc1708d14353");
            result.Add("br", "7ae4d7cfe48fd33a859b930f9b9c4cfadd963364901a6b60a4b42d23e30bc23e0bc6c38ded7a4c7fc648ca99d4dc51372ebb93d445967d0c74550b0e9111a604");
            result.Add("bs", "c2672d3a0735003193bb7bca8c0e736193f1ce24fff58e937b402bd62dc3b45d9b34097587a436700b96df67be6c1056dc5a4e7a534e5e924afe4eb23c262f16");
            result.Add("ca", "0795716383bf0a57906086d5106fd9aaa09f47d271639486f58d0d83a291b3cff8824752a71b905d17b97fdb900f53e6f5932d1d599f979ad6f8ade12252180c");
            result.Add("cak", "eacab314b24da0dc9ef67d2c855812708cd15b5e2080cfe62dedaed58312ab1b49ba85947615c45b53479fd712523b037a0b68c0779123c7a0354b0304a4fe1b");
            result.Add("cs", "766d9110dd4008680b96e569f74553abb0615ce1a8b330e1b8bbd43adf0fe611b4bb5491dd03e43bbddc6ebee8ef3ca31e3d8c6327fd9e960beefa73e8a8c60e");
            result.Add("cy", "aa041caf9c3dc4b0c85c52509f6eb346f083064fe87500c422d2ac321be542a42999eaa806b7400e9b14d7cb12be24766f7b02a65f72fbe0335cf71aacff5c6e");
            result.Add("da", "1b933a0ab3bcb1e72c5ba38f9102d6dacd29e839d10c7e2c5a1e75678fc71c0a1c29cadac43a1ccfb655f37b29841b619264dd3f497851b84039a6c52969d4e5");
            result.Add("de", "b6ee27bb7a173871d13d1010079c6167e19f7463f116fbc989714cf821e2c2b10d24c62e2e9ceb9372069cd54d0d63407fba50864a0edfa06e1c2fe0db118e56");
            result.Add("dsb", "e78ac4ad9e21c5b55ab13ce792b6bd1e417b6d21f34476812760651da847d26382629efa5f7fa277f54a515fe31620678645dba30fc2e42ab24f1094e8bbd620");
            result.Add("el", "af3ec26fc5a78df9c03c269283229a6002bc00d17a0b5cb50f2cf14261a5dc80b2704ed473fcebea605c5c7e2d3c66c969c66a236b583755307b9da6b24bf4ce");
            result.Add("en-GB", "9c819eba4980d8cd65c4de5fe992e894bfe30b1c91b1771d2f38891dcf02a98174397f623a963ff30dd4d8aa3213b8401d4d1e9af237d4db4518bfae1dba5ea2");
            result.Add("en-US", "c335e98abfc818022e53c98bc77045e80c513386215fd3d989f2816a590cf3b93a4961d2d3a996c4d78d376a53a0e789e6669401b13b5bd3656975576c7f1c74");
            result.Add("en-ZA", "ffae915eec8454ec5313886f005f9abfa31ce91fb55e50c04ce4dc4e6c22609954c213555817e6f21bc0f4e9cdd4677c59e58586ef3e43d79f17fbe0d666ce1a");
            result.Add("eo", "7cd2947428af1ff0f35e61422915bf25b74fbf5c73ee7853a5e2894ecdae34b0bd1fb7259d0389b3b0852d1985ad66b7faae4762f222c225a3d31688ddd700ca");
            result.Add("es-AR", "73d46440d31b9558d0d0cb9ea9dbc6b3e9666052b2d46fe70729633547006e7bd0bb43e1df4db50e1560d219f04b5bac9da37588cf7b5dd83c362f50c5bd19ba");
            result.Add("es-CL", "8274b6819d90c1405923dfc12c0deb2f8ece3bbac7cccba60b25c30c484e4b3a98451414dae7eba2309496fa367f37fb9aa65c4a174c1ca4b0feaebaa80659cc");
            result.Add("es-ES", "c41d325fa4c57a12e5550fd6d9956f50eaa69b3dfc106a423252a18045e7ee3bd0efca5a87db3dbbbc92e09c0ed3153007711839dd6be2f1fb635faf97c4be9a");
            result.Add("es-MX", "a63f3b3c8819d5d56b11e3280b81d489c2eeb533c2810bff983bdb0c98b151ab935ce054577fe2021036141c711bf185ff07e56c06341bb31b34d0e4725a6453");
            result.Add("et", "d58c5e33bf347c6cfaaa91d8a968be83c306c097b5515a1c342c9c7762da2aea0ecbafe3777893fe91da83fb9df4634f6b6e5f9fe02fe7ab2370c2eda8be9994");
            result.Add("eu", "36f2862d625338226020487ecbbf8d02cd360715b4daaa76469e7a23e40b5bcea55c8f8cb7ee79ef355289d76104774b08441d58dcd6e75b3a29b8e46b3b1e8b");
            result.Add("fa", "16ff6d96a9ef2ec237fb597419f259288c74fcaf99d9fcda0a37beff80b5e0be017eb2c795561531cc4f717e3aba4adcb41adda61462cbfdb6cdb4325a631224");
            result.Add("ff", "281c2d1f53f56e776a66802e00a439bde84fe248ee223ae53a99b7c85d7097f94a010787ef50c71e861afe15301eac1cc2a56e62cd2db417de92e7c42d0ce947");
            result.Add("fi", "06fe9cf926d6015fb009758e1331e333a1ceb4d8f15ceebb3f715b8cc1b4abe16e1f1c41bd1991be000248a38db01448d36a17cd89d30a257d7d0bce50b713f9");
            result.Add("fr", "b86595be02f51ee180c489b4cfbdcce6ebc427fc2bdb548033dab9653849afdc721d6f00d530182bc36ae37e9bd679b12934565ffa2e41f048a0e5a9f50d5423");
            result.Add("fy-NL", "7054e31051e46c3be194ec7b5108fa268dde427ef8e062bdd2d0511aa09667037687127f01be32ab1fc401eef6a09132a5dfdba016aa5b65bbb3d9546f864482");
            result.Add("ga-IE", "07c8c6b6dc74bab421710de9d5c07e6f14ca84c3e97ff6917b32fc4b26b443a2ccdc27ca8053fc340e82eecc545cac5a03c5b6d37dedbbc2d8252eafc7ece7ce");
            result.Add("gd", "8e07b0b14ad5a745ea1878b9519a2cdfbfc93c5afaac56f428f8c2b4cfef587fbcebcee3eae64f08388311864eca857e6284b550b6023ada3ce08422e979abc3");
            result.Add("gl", "12194a61f6d0223b53550e9735b18bebc7cc8c5e3b591c5ea120794c23c4d34d02be5a0d0aee04df3a73e46b62e82b324cda4cedcaec099e4012ba2bbd7d104f");
            result.Add("gn", "9c5a47a720d310db057208379fe6198dc2f32afa3d105094135376d5c4bfa76a89384d2beda5e21b9da479216f3c7c69ca56edad68f62af71d2841a989635d28");
            result.Add("gu-IN", "0d4fa3f051a0bb3b70dc091831622fcc8b0d7a0e7a1974b1432a846c719598423a72a7db7f594639a0a4e0c5978bd177520096b2949ba896842e9458188d3eef");
            result.Add("he", "c855e993ac5c71fc78648e2d1d961e5ea802e8bb558c3d47a579a1c91da539b80b10b62dd399f07810b6d1208b5cc2cf16a0754c7ecf5f49ece430e1ea0da056");
            result.Add("hi-IN", "de43b51a7924e2defe7ee93754baf11e335516db74565ef311df222128718d7fbc75a4a5609922dba1639ce472f165d0d2d5fe4ab18c7dae80f3a441544dc3c7");
            result.Add("hr", "82772934353678118f43b5f32552be27d1fa9cd8754b90a3e084e204daffdb81dcec83351d6629b9fba31cc4b2da3e777c593fc08fcbf52d550424712226a9bd");
            result.Add("hsb", "cc75841debc77e673a7b588200dda4b562fd5d35d4ed86b6611b335c9dbcb90b93c77fd824e7564fd301461899eb5fbbadb7aea6e185e1c5d3bf6e2b17c646af");
            result.Add("hu", "fccff9b21ffa5ceb6eef997155d4ede22ea6c4610eaefdcf0cdffdd00e7b525b208bf3460e2bbc0482742d87d5f6ce642f35a7eb809972ec2164eee5477b3ca3");
            result.Add("hy-AM", "b787f8e7230272591f5003c5a133db246e5deb398fe61ed8321a6fca87ea8959a15578aa6eb98506d64794be42dde382ace68f0ebc22c62933e737f327201a81");
            result.Add("id", "d3fede40950c6bc99e9e1abc9cf20758cd23c7ac9a356c6262b0663cfc8599fe9df14963299255053a5f337d346b5850de92c6092016ad8fe38f4e2f4ad60b67");
            result.Add("is", "393c0eb4c9a7f3f4d747e12f46a1aecb5c48cf6ff98fac02530e7bacaa1fc00311b17eac0cbff73c20c84f897570fc01f8464cc23e9a77b1325b342ab23ecb7d");
            result.Add("it", "51c167d07e88975e0774517ff492eb563b28263dff35610fe5901e9bd202c4b411d6ae7c830463ba704a203bac41905b24b9c4f9ad68016b6d31ce6be077d66d");
            result.Add("ja", "4e28e58258651c1d97e9544da3268d0b909442716861aba6815f3fa7eadb4f8bd48b1fc1fb1141c4ead74e5b75fb64bba03abb0a87108d05270755af9f697127");
            result.Add("ka", "6accb3df5409a88b67cbb2e36e1c91ba2e1b4b8e33f963151319e9d7087445414876d2cb8857e8799a32f633a89e18234d862d85d619a2251bec79988e1a0aee");
            result.Add("kab", "4a7e863fda831558eeac0db0c3716739e827d69c176e3a9bf47038af5bf6966396197243c948153ed47211c8f966d43d54d367a7b6edd99528c159c30eb16022");
            result.Add("kk", "c077f3d32396a52cadf37b72b53d56844073573681af727a859ea6213493419ce049486882c2a27a2271c863dafe7bfdb13d5c52db3a0d8892cf39c64f3ff7eb");
            result.Add("km", "c413d5aa7678853810a673c3b205e3ea5379afea084e3c674732aa7ffeebe190de4c958b97b614e8e4a0fc7c902af1b2bbfbe2b173ea1860e21f6e0816510728");
            result.Add("kn", "79f1614f7cf49739d187f270a78e159a0864fcb4fa115e8647ddd23667533941b11d7f2a4690ae426e8ba437239880ed90ef77685699a0f90d9872a88b5aab60");
            result.Add("ko", "59ee694813f5adbb61ff1686eae8947723d0f56f34108addfb4e9e237809cf2e027d175c34435204d6d2f74b7cdc9aab72a91e41fa73c95085148c5a2e07f0bd");
            result.Add("lij", "927232532ac542aa189a0f32746219735eb76195a7a50e5d3c13a3d44dafee1786916d9a430f4a2990c4e9d5337e340a288bcf1193b7ae49dcbce164c3bfb04f");
            result.Add("lt", "45607111e864a6bfc2580b845ed1d1421c835f7df7d850e2277136c21715f5a8bb3db3f2dd005ae558efd338926f16c4f7a9df2375b3d06dab29a88dc9f93bfb");
            result.Add("lv", "f571c1c1df72e35537d53c8f8194e1a351183ac1850714e4cd5294b3b3f4e9af9a57ae7634bdd63005ac1df34fcbbfef8330e218effae7a48449952b67cc4dd2");
            result.Add("mai", "ce9c1ae4bad338d78af57b84a553daf8ed79dce7d7ac2a6a1e75023347752d95d8a7f980977dba1350b9c2bbea6ac10b654510c613d115a39c01e49e6f98d5bf");
            result.Add("mk", "fce9f55cf16751ddba0429d76ebb69b7d9a1a2b0a5813a3747586b9d834f6f90847e2498bcaada284155968b84c162bc8fd9713a5992686c33c253387a9cb2f8");
            result.Add("ml", "c63835e3c4110cb1f94c2c103aca02d32412047e8442836465d9ffd28bf0c395117d9f9f192ebd26153dd2460f1b971cede9caa9dc9de3266693b433ff63d992");
            result.Add("mr", "e8051bc668bbd353fe51290db76cea6a10ca8d4f507be6c6837da7bf9183af5ee97ebb1cdffe40b5d51dbd5191cd37ff113457f82c684f01991a4dce143d302c");
            result.Add("ms", "cb59bf7df401709e0f621350297c1350b3aacd600fc36f3062b5029561c5c3e974cafbfa9b892c067e957af2d40d1e96634d2e8068638aed1bfe274b95e4e674");
            result.Add("my", "fe63f16d981f38b9494945130e93a75d0671bbb131907af4c27a4784a4cc730d8fe8fd60cec0104812cbeb7d26ebe7666ed3192a195e37c1b5eebce3f953131d");
            result.Add("nb-NO", "44a655d1c7dadc15324d1865cfb5e43a0fed14de0a3110733c205ebedcd453132f13c59d714b245ed97120a6dd9ba29e4b30837f2738869a378e8825dd8d0adb");
            result.Add("nl", "5a2fff8f1c6e534a2aad38b30ec9dfe4b87752489e062357cb588865a63bd5a7856b327b5ef6af22f1d930ddb2c5335daa353ebc4d5ff25dad95350e106808aa");
            result.Add("nn-NO", "e1202e1a0b15b4ea56693533be4c309ed17b0fd57281ca762c15a579bd59da9654d43401def7228d89cdb838a0b916ec609274b8b47b4d6dca7839f6c5669593");
            result.Add("or", "0fe0351a1d4556184110896c2c02361610363b52f0a92229e8d4207c7bd497aea3489f840613f351b1b69259a27263ddb3ce53e09a170dcf8375d22ad2b4b291");
            result.Add("pa-IN", "b1061cd172f24ff8f4210e6a0184eb2534c2f9b8dc9586e89a5dd0240ca52ab35de4c6075aa4454d85c9c077612dff53ac542ae06dc18dda0ef81448ddfb6e0e");
            result.Add("pl", "b2aafb6bdb1a406fb153f8c68ac06f4eec112411c060eb9ff1dffa07e2241a71eca680fd3f5df7d06e0bd4ebaaf3ec2d3ecca595f308e9a65d207bdae2749054");
            result.Add("pt-BR", "464906ec7b10fba5c208d9ffb4b2d4f074d46fd42a8e06ee8ee3c994d3298914d1d2b9f8b74da6fd6ac23c8e59f5743582c90a3f9d64e7b509cd6b9aca23e8dc");
            result.Add("pt-PT", "0efe314fb7955dc7458a05b9ff543618eda078228832cb5e0d16c66f90786ac8bd49535492586f371134d5aa0d904399831b858e7e8830fc28f67dfbfec24abf");
            result.Add("rm", "bc3e82f403576d5aca49eca7862db2159b67c818270ae155fede974cf13eb9123cd9c9af4fd568748cb8b44bca2930533b997e9bcb32288ee56ad06969909d3d");
            result.Add("ro", "926d31ab8ae0cd459871c9a1f5096fdf6b2f4b534eba175aec78f25e346ab7ea9089c7382845481393793e7ec17a1d073f3a7e25a1990cb7414a5c322314ab27");
            result.Add("ru", "b427ec69c4007384fc7c32b496abfd5fb5b177608115d787cd283acf600d99d223dd2b82510e6715589c47009f825af86078de49b26b7cee17e1f7ce6e9d237e");
            result.Add("si", "7ee971328d1b50fa2f4653d091ab2345afe658274a65d8271a6d1e4bafde4e7ac24de353eab0e6a855da986a6fd4ef1a5b4f8882ac3b94c080e0174697b5ac38");
            result.Add("sk", "d587889fdb948079a64ba71e7974ea680eec52c90d5d80565867c6fa74a4daa1d2e3106ed4bf09ca83a06d5a1f9f127e087d100db3c1882c2cb413180388056b");
            result.Add("sl", "feff3bd0bc0492fb3bc78d31b97e5975e24c71a96bbe2dc8aa15b5cc7f7d4c5ac8b14e3b65650beca7071d26f6475ae5b835df7a57e3d755a9ad885042c35101");
            result.Add("son", "7fd7439becc3d71a891283f2098f8cfe59649b32c78f7af5ea63c9cf2a6c3b2f1f5c100f29b9513314d7e442e50dbaf4c9d4c31ec7a0a3f08f637d03d534ef2b");
            result.Add("sq", "087854854de980cf9b77994fa997770c803922c54d488c402650f3b0c8180da59d92fb0a4dd0c92975983d25ac3f3a677b164d76940bfff6076c9db49023f109");
            result.Add("sr", "14865dd58841ea39c3227d63f77a4c4c4b9971b4402e8fd56c61ad26e3c934a83e32bb628524ba174f6023568f560d7019e2d2a21d9acbbce2cb012f9ec5ae6b");
            result.Add("sv-SE", "4198e656bdd51fa2c1dc4a0d8056966f6335f0c43e5dfc5dabb641bd6f7de7caed6e28c7b063180ac5528dbb6a28f239f85910cc815bc48cd53e18dd52079f1c");
            result.Add("ta", "3e8be0710050ae8e86151f1f43c6f2117beb08f55446743f8ff0a8310db86ec408f7bbb2e70a500fcdb82e8959b3771b84f10c6d740284c54bde399bcf9680fd");
            result.Add("te", "55d0874c055f890645d24ee516ef13dbcc5294f0eccccde71ab1cb792be7b032322171364e532832423a0f260d06233a71d32311a597b641eba31f1c2fb6c397");
            result.Add("th", "443b7baa56e2f196c318104f543d366900becaff450b50045bcd0de78e534ff60edab05d9813fdbbea1ca82416a5431c9a7b8af17bb482b07b3a9f6aa5e7793d");
            result.Add("tr", "8735254547af843fea7055ed654f56d2ad73d5f02bf0622d73155f0f615a2c5bd90aa4394cc947e406e27c8157b013e9e6e6fe0cb4162f125bbabddc208a6abb");
            result.Add("uk", "55ec3e183e56e69ae0aba8094cfe534c17ff030e7fff1da0bbde497e6880665a80a766ae3ed8ac43810631ed96d2fc5bfdd25e7a592210a823dea411cae4ebc1");
            result.Add("ur", "0ca389907731f7f41e0fd9919b29539ed99236e7cc583a345ee3339599af011dde84f514aee071738f7465c1a773a93f2a04597c6d8b6cb65ec8f089c9c1d97d");
            result.Add("uz", "445776bc462d65b0e035c20b93bccc43f806927f7d73f3806eb7190c3056211aaeee715046290a5c165672013eff4639a64a33789f4d578c250a986f64eefc91");
            result.Add("vi", "2006b3e5b9405693453f3b1f1f9b5ccd6466d8ec3ae8ff0cbf12fe3bf32fe3c9944e0c78f7abf789a181519e2121f235e9a3b692b6eac0aa9a9da1c8049ffc04");
            result.Add("xh", "b0a9d5d210cd1c347debb9d79fbbd57df05a32c5ce95acbfb181a4618d57c2cc1a752d830f08f18e6cc8478dea5e6b3c2ea1955c6240e9d20232ee654bdcac4a");
            result.Add("zh-CN", "071e0b2dc4742e4f518be7e9fc1cf85d4bbd399fe5ae3125aa3654b2c43e79e07f02c1f92265c1cef7f11ac74f3cd768636b19eb57282b1a242c6c18750cab4d");
            result.Add("zh-TW", "0459352b993da1e4bfbd7e7ecb9fb9fbce8262c12f64944a2d6f0fbd3cd598eaa6c770183b39efc671e0234ab9a43efa4e005c9fd61441da870da4f52e351eca");

            return result;
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/55.0.2/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "7ffaddd67fff4919fae91ce6cfb8816feb5a8930d1692d59049314990ecdb1264702905da032f99f10ae4b3e398b798a02027ae9ba0f64d1fda41a320e05e143");
            result.Add("af", "f3b3e8ed99b974a2143b0bd4fb6608add2322cbd0c311491f1435930776d719ea4d3cb3f4ae1d53fbd45c954a5028d168d56193e01814fb82d82e3b38d3a3162");
            result.Add("an", "19daba63c723efd825bc3f64b3fc02d00eb90b08ac3557b7a19401d4bed5158a338a19f42a13e93b61bdc3b99d6b5d76954e58c3901c374d186d460e4cca66c2");
            result.Add("ar", "f273f3f6a262410e701b5a1b9ab4320c0e42e4cd12195de749a867f597332b24a613dee28df026285e3567e12c2e15109384e20463177d8f6545a91d7e792bda");
            result.Add("as", "25a3b76bd52daac8b1ddd5706c7cac69fe183320163a35e914fb44708bad4668276adf92f9c2f9e463d89948182f1736c977750b433eba2fba7824d05c7c78f3");
            result.Add("ast", "43d4d52baa19b3de79e183a9887333022d7efe4e790cab5a8a720a4a8a39f976b697e96e3d55035d14c2a4ec068f39a02c3d7b8d1f1038b802feba376e1ad910");
            result.Add("az", "73ae3a1574681908ece24e4a42c01af090c1d8621f3b992adb47ebd06c418e776401487a29de015cc5fedb33328560244ff1b396171ecb4e437f3011f56e4138");
            result.Add("be", "e960be4de9f460c3a7af3f709f6a2c232d701ffab2a5f1d371f21070205db5b4946fde21f718aee1730602970c1120a7f582b77332de76da31e79875b740f866");
            result.Add("bg", "6f1687e096939c161bf6513e710f32ac63592488e6f23d8e0a9e101a1ea4a4814acc24e6ee9c8e2dd99d7f08dd184028acb775de1bd218ccd0fe0d3a5ab0939f");
            result.Add("bn-BD", "5142002c561d4dab8fec37986c08181cfb2b70aec28be2b4c87906d8b59b496f76ac2737b2a16e4d590e5da0160a7d93903f0c80130f43f535dc04d9e264d289");
            result.Add("bn-IN", "8d8664784e918ddf2b37d2b7eae0922af3e764f6a5fd89b78a3fb7e6ebd19d22a03515e92d5a3abcfae93954b267d9350387d89fd4a464e73834c4c7dcf24ef3");
            result.Add("br", "2fb7a566dd2258678b6411b88869a0150fc952b86739f6f42df9061991b3dd99f5deb3597669485aee1f7825d0483a39f89254bd6ef60b770fb68da2b7db1422");
            result.Add("bs", "954637a09f7339453fb629cd29d7d82906c64faeeb15069d06b5b7f05a2ae5d4e4e367f04cd03ad4c4494eefb4c0390452aa8499590043019dcc5556fa631e0c");
            result.Add("ca", "49052e56d8e714143b00ffec180abb47ee9940c892a8a21bb6d4df5bcdfc727f22739d93e747487d361c26eacc1a0b30b4c23dca879479a0b92a292a69191e0e");
            result.Add("cak", "1404ca0eab6e0ca4ef9c2e401662c792e7314c64d6960053271d832c7246fe460da2f66dffa0c9193a1105a0a2b8fb23c82c08a1174e05dfb7844d93cc3baeb4");
            result.Add("cs", "8175390c87cf827fb6cb8eb7e6fefbf590d2931c94b7bb220da788144e17dbd38df46870a43a3fb1917fe1a58f7bea300776bdec2bfd1176702e9b62207ba55f");
            result.Add("cy", "1425c8635764b7abaa0fcc4db5070f64ee169688be44cd47afcad5d0cb5ee54a1d1f6cda583f63857f522112b3ab37a0fc65c66a7c2af5e1a2698c190437c968");
            result.Add("da", "d7d544052d575a632b02e739acc900ec8cbb69c4835a2f299298b1a8ea960f95b459c454b4229eb5a5375a2abedacaff08b280b6830e52e22c41638bd3991530");
            result.Add("de", "4ceb4ad475e0c3b76ca5f4d6313323b7dcb3b860e927c31956645b5146e7d2976587d4e55905a7ea0576b98a67c44fe68830682a88c910d84c1789062c634747");
            result.Add("dsb", "40f2bd291a18255427370180d35da727f62cca999908872418b6de7b29ee688d8337c058673bb690525f36dd075bc983b0250a35423900ccb702926a2bb2cae0");
            result.Add("el", "cc8e8ab96a57aa2c3afc535d09f26247c5de3bedf2183cdc9e47e73cb6cceec376e54829ede1399bef0ec1a505ba2bf07469794c1cbbff3625f147cfdad63ff2");
            result.Add("en-GB", "90d9be9ba57f92e7cd40f76a51c96373b3e01e03eecdc100484ec67909be44308694330e99e158de5841847c6afe4c4e9c36c35cbc4d5d303c6a7122a8cab5d0");
            result.Add("en-US", "ec95e65ee85198c3b5506cbb10404f2c29f202c1ae76bb0238d402ae37edc0f4a6b2c01611192fb31ea11359657d5e3949b0443e262d340d9d92f311fb256ee4");
            result.Add("en-ZA", "e6e80da2ae5046c29285bfccfc0aa2ee57d869814c00c21b89822a571ba3a357edc5cb6b9ada8b7f72873e7dc7125ebce45456cdc469c0a417ad8c336926d80d");
            result.Add("eo", "2c039a82ad99e4512a4897e57a9912de2f7694aaef92656a3d1853ba5a31ecbee0dd67c7780381fc84651128f76e1658e64ff1c845c4a78255a9dab089154ff1");
            result.Add("es-AR", "e61e4c72b7941110c37c7df310a62e887016494509c5a6a5a6d45c431da4ee7692c7d9732d4dbda4c7324d3efa4558b94c2168195d759b591e78b1fb1fd6dd89");
            result.Add("es-CL", "1bc322c0b1dc7c94648376b709e4107b46c975c99f759484b96b14ed4b4c2be6a8e532a6f48a8cc5741dfb6ec353768b8ec933fb451c9ca8c36477d779673c43");
            result.Add("es-ES", "87a7f4e52fe7cf2d8a2fba285d5cfb6863e963d94750b00fa950114ffe91690c4b799389df11e582dd6352e8a588a35199009ee1dc74d7795933fb55b9e8e618");
            result.Add("es-MX", "114c0db6bc274c52b6def4e270114d1937d9066c709c81868aa5beaf3eb4123287ec40ef874492ca60892ef9ab34c7cb679198fd92ce1082517f1e11ae30f100");
            result.Add("et", "295b6e58ec8b6d14d1ea472afd2a787e8b733282cc52c76146adda5d38790d22e09e11332aaa3f03e9a59da2e53d16c91a5c51d00397ce9b574680a0d1d79ba8");
            result.Add("eu", "5fab354bab48e96353b02952cb9364259dcde7f09a5bb923a792618afc56f48dab0ee69b68412da7464449fab20e8b4cc30caa0f5ddd748bb42f0307328eecd0");
            result.Add("fa", "8768cffbe6c4950fb8fdad3b33dfffc9c94d8a465c18031a54a0b137b11be2ec7c40c6142269bfaea88cd94b5680bf4928afbba7283fde01614a965779d6b52e");
            result.Add("ff", "806262be0114ac7ee8ec25a526eae685c61ba280004fdcfa5ba4e71e626c380b132a89bd20426b3f6f2c0fb9a06e352d2361afc7a8eda6187174e81cb62e8d0a");
            result.Add("fi", "b18a19fa2ab4aa87f223363f357c257a325f76ff4ccbacd6c86519a0fe28cd36b3a7482cc5c6f3beb26d341778ffff9f1f0acbb47d307b9a47826d54a317d259");
            result.Add("fr", "2192b695a4b659ff5e6b4230fdf4560ec51fdd85f56c62095abae68acee0942202d516f72105f5ab93dd7dbde7356a30cae516e41580216ae6b8cb086e51219f");
            result.Add("fy-NL", "92b173cb99e37e80eaa1b5dbf055752c9b523a3cec3d6e8cc0d260f1ad4de793af4e22b6665cdde30ac79ad2b5e2ca4b64ccb68f892d7fec7fe38b9bba28b501");
            result.Add("ga-IE", "dcef4d2e6f1ee4dd5eb8268b5e81734cc42cace8ec30e360df3f935c3366338e300b3fe91820d66ef1c10772e316b1e11e9fc94d959c94cbc39b869d0bff2974");
            result.Add("gd", "c260352ca7c9813a807b958428739ec82b3f6e4aeb8f2b5a66f5b0e2722b8670fb5f1386b8a1447b799a17d8164ec6db84f1a430b8e6b7b8a990a5dceb497e58");
            result.Add("gl", "a86e60560f898d2c40bc982f86a1107ea2570de1940beb713c9cdb46657fc4e145252fc00376a573aaca027c9d5b78c4e11e20ab1c85a7127c011d723e42a055");
            result.Add("gn", "35e5ef454d68162c4d1fd105fc7a0af79b16098b4c02504ad5177cea3eab8949b7351da8ce2afc72da102acac10c53928f47c2bf6073d91225694c74d99621bf");
            result.Add("gu-IN", "9aa5cd84ef663321c04bb1ee71425731f2fd86c4e4aa9c48fa888197e57f74132d4b323d8427b32c22a603b7be02a8c6cfa3093359197fbde4237edad424336b");
            result.Add("he", "4042a54b3beba6ff72836c86c6754a1dceb2f267f63d1f444964540c0b4f9f97cfae1f29bc7e018ffb76015e0edd21eb1d08d314e1bc24f63a5e1b4ebde6684a");
            result.Add("hi-IN", "55933c358ffbcdf5a7292466590cda6a883cf0936a1b78863cd202713d6e371d65d3951291913107897266ce400932491bf50a8df3098d6e0935cd3f66f1f2f4");
            result.Add("hr", "d02424d3ac55cb5e148206df4e885d868bc1e5bf3a6c05f44b06a2b1cf5daf17a71090aa2d287d904b21bb73306a951058684b6642ed5e4b6f2527854f25e2d0");
            result.Add("hsb", "4011bf3cc0a238ed4145f1ceb72546eaa0f50be29d027ad9fcdc24e8fa5c7551723cb62fe670cc291d407ed69ba0d4bb1c7ab23f9580a91281be2d2318f322e5");
            result.Add("hu", "0757da134111ad07259cfbfa4ea97299c74734f0a10f3d9d17bc608a3f03ce78b9c27b1f74bf5a2a4f3a1895d297f1953239721d3e98c72c5294b56f0fa01f6b");
            result.Add("hy-AM", "adc0cf0f94b4dbb1421d6f7281972f38f0dbf797eb71cc573585680e4c12900461161a5027133a327bbad5b8c08b8d0dba5be4aaf376d27da9cdf0018f500419");
            result.Add("id", "a3c1329463a5aed3ea13bf8cda8f582cb855a2b307bb2b18de1ba7ab0cc670258764a382a53c6b368ce7240b38957d0abd7caa9e56f77911f340283bb40264c9");
            result.Add("is", "7fbd45e2a5c01f9fe2d12f9b1da5428a0d4c190ee420f943d263184f3c234ad826a3405704574b9cf800979059fb1f518b4a26c6731836a866d38b8eb64984ec");
            result.Add("it", "ce343e18585288a1b3b1046bc4fb3d4d2a57080d8a837193a5589dd65159a06bc0bcf6cdb09dd55c10ee0e2d298213d0a8361c9fc8b81a52e70bc9134b298780");
            result.Add("ja", "8263ed680e7d56bf704645923e46a6b08b227fbc5aebd336cee0f23a8828683a328aee9d89c215361546344e2cfe41d2aa2636130f58cbbee26681894748f5d8");
            result.Add("ka", "5a827a29804c0b08030535a880c5abf9b6ee7f19d35ad4ecb3e8f86bf328ecae58164e6b66d5f8de14ba956c28f186e39f144e3d9b375d0854be402fa2e31d62");
            result.Add("kab", "d797dda0ac66de844283f7343713b7afffb60692f13a1df01a3f1bd2ec596fa4886ce44bf425a72cf79e1010e6dad3c4fa6d75fd9fa2c2601bf81e59604eefd6");
            result.Add("kk", "b6cbe154a16752de5f2201cd22bc94d1f3f9d2b28523ac215bd10c9731a0e5a96275155c12987dbfc7dafbb70b376d9ccd1a59f3ae64cd9444280f3f96dfedf4");
            result.Add("km", "388ac1527dd485995bc3ba1153e4170525805576648965b0408793420a65d7eef08691750f4c004385118deb87f79bbd7c3a01484efe88e543c9707d5f1e2fec");
            result.Add("kn", "3de5ad29598851cf749515e637ef8ea5ae9945fe0779fe5af2da839b461cd3f6085219c2c6f912c37f60f3f89a099a89a2cb879a46460b39892bacd81b622ec6");
            result.Add("ko", "6b156247dbaed8280d927917b2995770238771809608ad571488c5357c72586ee5ca51529277f1aac3ada1e46558909eace25448fcc72d44e3ee2924d078f586");
            result.Add("lij", "c7c0ec1d9d8b0a2299337598dcab9dad8e6aaf256316836b8ff06e75db66a69ac5aed31a5519e0c8a9bb45bb6dd64b425b091f103d031329e68dcbe1b379c93d");
            result.Add("lt", "11aa20385f7da486aefda59872e4780115e9fde516154769724409ed791f92615c62dff25c113011de3a4f28518c17f0007ac4a83db76074d66720eeadc09d70");
            result.Add("lv", "4e5a0b36a38ce807ab9aaa21f3d26c55dbc7493f1d8780c769ea05e99ba727614dc6c4ec3fd072d3838a19ecbc889ced25a4bb3ec9ed60f00e6e0af323a02325");
            result.Add("mai", "1b26bd4746a46f8c84d6c48d5e55d4e8b5102d4fc3a1885cede7b6b622e94d34864282212e197bab7a2d3d889fb82df6f03693decda4f3a296cc339424a822ac");
            result.Add("mk", "8b694610b7cce3c0e86d527627661d9d8fed58648d8418504fae866d91d373382c59fae376c8ebd70beacc2256bdd0bfc2e970aca5adedd1b5809f860ad93d23");
            result.Add("ml", "1f4dfce908b5cadc308e7e267cc1aa465ad349781126ec560b40aff486360bd5616ee732ee3a6a179645adc0887b96e31a4622cc6d489485984dec8d9a98b59e");
            result.Add("mr", "7d87618356840a7e86ea607b637369052f68b7cd2adf6b48ceaf77e6e9d55b786285f096832f0c83dd45a94ccd91e9f400af9be9e015d0c3aa4e81839cdb90b6");
            result.Add("ms", "323aeefd904d75e381fd86d2fb71efa4edccb1ceb1ed672ce5d5b5a6d5c2666069f1734f0067565d188647845b5d020361f50d59b4916a639d38e2e685dd62c6");
            result.Add("my", "7f02dda9bd5691963095a042e5ab001b80ed80445001c76b1c9cc3cf4f701822b1a04ffe724d48f4aa559491f0e5afb6263e9a1b500f4396da29c32623c4f358");
            result.Add("nb-NO", "49e5041b8af990e5e6e10d407ad7632d4115f30353ab343da6ff4d2da3ae1a5e9ebc4a60b39bdb1765868adfa2a2bd8c5593b473dac259cefbb6a4f9fa67fec2");
            result.Add("nl", "a5dc6f79e01d83e0cb744fa12308193ed9f3cd34d2772fb59d9eb842bcdaa9ab82bd44f94263c0d7254a0314894b873bd8050620c29c9c4bd12bc9c28f9ef117");
            result.Add("nn-NO", "cb4f63cc34807f80f8428e4de9cd6e1508a231cf90037dee988a38140f45b0894a280ac82ac18706688935b8bc2a8e67626e88d962cc5623b8abf8c1430f7ec6");
            result.Add("or", "052f4412ce1ba78c3fd96f73b501dee1f3820739de95a7d9b8ef4f1abebf88e3ec46288fadf00029c9fd73ffb851b474e58c9cdf347c29203fa71250874317d3");
            result.Add("pa-IN", "a1a0455cc99abc0886ac99ab1dd169c6e4822f38478ea28fae2539fd3d607c328d5de583555e0fb9a471c90deaf5b1f351be3e420b9e22c375e050583d158c3e");
            result.Add("pl", "f01ea460efd3aacbbb733dbc4d08dec54d9994b91d237f7386b5d64147822eb44289fb4bd2e2f2dd40ca2968ae9ba0db9ae9bc04def06ee61111fb2f5f690fc5");
            result.Add("pt-BR", "e043fd479e3dba6d079ebcd163f63607d6b33064288dbf83fa8d801c3fbdbb38ed7dee867b3d284b5e97b6d3df9d1c50fc463a0ce94249e10df838f18392221c");
            result.Add("pt-PT", "481a722096480698e391f0416fee11fdb05466cadbc8497258d119b7927a1d2146240c5eaf4cd5c30d274e46b74da55eb70f652c20db699521d5002352c9600d");
            result.Add("rm", "9a5aa8704d83ec609eabdd61351f8a1bdbbc7caf3558b6ad561ee82d143609ab1d65f7617c308715a03e769a7bfafb38b3a3dcc2ee4be1b71f88f1d710d4f23d");
            result.Add("ro", "d087d7efbee168de2bb932c6060d95ed3dbefde57b56c423533527d09455aae9af40c9d445a0ae85900625fd490107799caa03e7f35ceb15837b5319a3e95b73");
            result.Add("ru", "b93db3e3053efde862ca79f69c139ca20028f5b6136e5659556d7d5b54fd73773ca23cd45ab5ddd74ce66758be86eb0809376bf387433e87aa261aff47c816ee");
            result.Add("si", "044406e736f2dbc8f7f6524aaa39396151c6d8eb39c87c3e8b564783e4f57c16f8802ad35f6c721b87508cff1f187b49a959f2f5c61c86ace2f7c0f37950bb4a");
            result.Add("sk", "b4e44eacd5921f7c522fec0dacafaaab0ecdb6e6a6c8db38f99758c9ed41328a34eb29d68f36e635627de26d9cc30b2a7949682649aebd3f088413eef32e6eaa");
            result.Add("sl", "583f93178c65b5a2e2e7c93fa7bd09c9cbc00ca97aff6a0b3f9ff9a0be50f5343f81b4fb47344afd05f712312632536040a1610eb7e0c75b92ca4e11e60b5939");
            result.Add("son", "06e307b0a4d62c036f202912cb3d5e095a76247b14a7ee10ed132c7a95f11ae89c44fc60b3a6cda6f2647d10e7441606a8bce4ebb647e94a4f0d6fa6f2352132");
            result.Add("sq", "972ab1f7963540ba68c0393950023c10651f8970c345958e2dd82092d818893bf6a8628fc251401ed8a040347ebd6168be336f5c34c4c6dcd18e1c811423aeb9");
            result.Add("sr", "b301c1b7e916698c71fe1c16a2fd4eebc5d373acedd4f94b05070d60b7d7a689757f60a62576abc7624e0bd6d616c4dbae171ec213ef53073ae00d32ae4caff1");
            result.Add("sv-SE", "4d6975a2f1f25493801b40e4c7d5565ac0717d3acc0afc5193792ceab281f6d0b68b76b9291b81ada1e1f4e5cb76fb57151e680ebd165bc2265dd51d24ba3ed5");
            result.Add("ta", "2f304662ce99ea149ccbc9a4ba8074e68c3d2f0755fbeb8170f740b3e2d0f071c7fb48e6b1b6fc42b740f9cd0bf2877a85e90dab7d2e7871ef90bde443b9f593");
            result.Add("te", "c1daf59576a048dcae245f6ce25bd3cb6dcdcc8b7ab1ffe538349521b686a40a9c94ef86d67506cc1ee4bb9165edde5b23332c66f42d0a7ca3496094bfe23c55");
            result.Add("th", "b44c5e39bfd3a6a098434db1a656d0bd3b2a66ed2de92ecdacc4d629d0e0aa9bdcf9d89a065640c545ad9d628240b83c0b8cefc003f7a401eff69337e007e15c");
            result.Add("tr", "703cc3ea3d0ca879ae1e8c9143c64f68bddc666ea02bc11b492b78aa53b95b4adb8e9a5afd4906669512ba76a4d7fe9f030971844b1ddae906177803d7124b5c");
            result.Add("uk", "e77d49496eb223068bfecf6ac2324d236aed3c83fbbb6525a95b76a1d8273b21acf3e8b6e9c4c8342a42cab1987d71a0e59bb1d9e7c7435011c516dbd2f496ca");
            result.Add("ur", "79d6eefc61f0caf40d2c6ae4199bb1e0a2308fdfde783c8ca3971e93450b7fca1df44d4a87f59d401ee6a4571e61b445b845a595d627cde348adcf2ec3d4c3c7");
            result.Add("uz", "4c1c710e8be92feb48218e631af366da72e697e19087b5363a71d7fe7e0ab473d62548441ac55a7884ad7176db26fc569b31854b71114efd39b0ce8f76ed9d09");
            result.Add("vi", "56313ca9878a876783d6b4ae7966dcf6d704f25fe72fac21fb3826c5ec00589cd5c617ab99e65a99002a50d8bee69473417a99d7f212be4034a5da9ab3b7876a");
            result.Add("xh", "881164a674c51e26af3ace4259f0cc0e85da1a0720f9a40812cf30a9c2733eb8e2d05855b08b12b1ce477df3136831c7304a17631367f395f034778ea4385a23");
            result.Add("zh-CN", "8dab2cd0973e2b3d05f96cdb35b8687d1cef60730e9d46027016f0d40a8bda025ded728245ccdbae1fce2edd7cf1ca95c5f7af3a7fbbd4e0828d37e3092d04cd");
            result.Add("zh-TW", "680ef4774dc7f52b99ed05e239f959097fa6236b04b4688523ee4d2f672ee3be4533dbf568d476e67734db408a96c63b157fe8b4b8acf7c85272787bc8b9c0b3");

            return result;
        }


        /// <summary>
        /// gets an enumerable collection of valid language codes
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "55.0.2";
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                //32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox"),
                //64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox")
                    );
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// tries to find the newest version number of Firefox
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// tries to get the checksums of the newer version
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Debug("Searcing for newer version of Firefox...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            //If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // failure occurred
                return null;
            //replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } //class
} //namespace
