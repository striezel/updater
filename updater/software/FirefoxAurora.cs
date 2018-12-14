/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "65.0b4";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/65.0b4/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "d4fc3d9523537ad138aaa25004b6464ab3910e6186146013ce949e321c20bd3ebdcca08cb853f8cf8e7d6813a5a92b95c9e1e8cfac58fcb072545178bb1c511e");
            result.Add("af", "b1dc0cb9386956b07f88d1508fadf914da04aa7b806599aeecf27437cd54826ccd0b8960d1f122ea4a9ff6fe71232c64beef0c8f2e61abf76d912690d8fe4ff1");
            result.Add("an", "fc05c01149c33ca00dbee2926dc5e3ac198e7be3b3ba44abb887aa2505b584abd8507364d84808bfde41da996539e6477d05bcb06582acfc6b96aa38e1d41012");
            result.Add("ar", "0047ea4056ff7236e1a4067d669a67b573bdb7fd7f1e9ba40c4a43eaeb82d742f401202b4ea1940f1298ce7f5d260c074491ffbb549712f0a466cb0a023ce122");
            result.Add("as", "bf85cc6770daabcedba3c61f2389ac11b309ea437a5eb01a345e35576343b575fe48d5fa2bc20b0753728bffa724563345a41e99d3af4fe1cf598ec236669fc2");
            result.Add("ast", "e9942b2613c387998fb190f726af691be5a0b75e6dd087dbd873650f96329c3fbd4db742f785bcf6a69ccc146af3e2520e60134ce9a7d9b65dead688b9ad6b49");
            result.Add("az", "36272ea36ac24955cb1c3c7f5b5d4355a8b2c66c70de459a9106e1876807580e5c2b30c303d3181a03a1ef2bd67ed155e443935916a07b581369e7ab3e90488e");
            result.Add("be", "c01b44237bf71ea7eca0d610d559f735557350f48684c0c9dd9317fd83ae3ec8599535ce61ab21b67435faa19dae61f117ff6d974fe10d081df135270ae6dbe1");
            result.Add("bg", "af0b122f28354bce705f88778e172559c71720dcdb3db9356925eb86aa28ee60e29381a0deae419a56d3a04aa2b1bb8499e772d3827731b83bd20605716c9321");
            result.Add("bn-BD", "46a3772b22905d9c6a965da7a0a66751b3a0d64ae07f989badfb3be466887e7cb7a3c19f365dab84b4545a7e96965703f845a7f821bec0ccbcd6d6b63293a9ad");
            result.Add("bn-IN", "6aac577d351bbc2f26c68c96d191b91d389815c81afd506944b4e6d60f49c0461c01a66f0dcfe5562f8eec6090340d53aa9f9dd721bc520fb490ed610a0a5335");
            result.Add("br", "99bae03c667ee2793caa67e647b262b8a06f105d1ab853616924b44d6e691446d6fb3e7584b5e39b45045ed235bbf2566700cdd75ffe655ce11ae66dc434f42b");
            result.Add("bs", "bc4495be7dcd2b8700f68c7093e005a9ef3c1cd1f62b91e2231d11bb2c6c2f2a476d8e445fa0a73740e11f5f7874b71d5ff09762783de2e4e1932020165d4381");
            result.Add("ca", "4f38a7e8c2108b1a3b0b3554900d5c51669445b3a390afa1e3c9d55677036eb33b8d8e52c20f0054f89624f6dc2df306a62292e4269b6ca1214d3950c20c8c7b");
            result.Add("cak", "15276ad6d3bbe0b35687c294ec1be3c4406bd37f44cc8317f84e4b1e30a5664db5d7144311b6ad6c5cc897b2e9fafe19b6578bd1b9a44ad5c5b479297d9e5a6a");
            result.Add("cs", "1297b260ff8c805c8ef8811bc200612e0da69edf257bc49acc3d351f70cb48bcc87373e2d11049b73816122b93ebc3fbda8d29e27c0f08d79b671925e144545d");
            result.Add("cy", "87e9012ce4d6699a221a4ed530badfac60b7be9c3e902297d9945b9792e609a7fa9738462ad5aa80a596d63ac55e6f6d64b044354b0d547291a41b8b774c943a");
            result.Add("da", "1f2a96ba577858634cb647bc7638964b53e0626060d2e731cdc5981244d19247567dc20cbf5ed80b4cca70f17dce2195f09e361f1482187c18ffd80f97e36fc9");
            result.Add("de", "7179dae4838547b483926e4e5906be242a927d1326fa7425f79c474bed4d73c3b39b99ccd530c289c79ce91695d6f2d45ca1a40b37c05d441a1be77aa076d820");
            result.Add("dsb", "3520149e27b4518df200019c34d7a5bb5f6d9340c3e924409d0120b40f2423db3a6f8deb24ac2b8c05e7defcb8fe9ca024d4ee3f380786fce5b708f34e4cdeca");
            result.Add("el", "b3efec4c6a19e07af706d809c9f821f0c2e272944e2cf45bfd73bb749a8d70e1452ed6c8dea50001cbf9b0e3e5a4b9b4fd01faaa3fc47f8187c4ca012b17d1ec");
            result.Add("en-CA", "14ccb010057ac6a79f73084e8048eb7f720f4c95ca1d68cd1d235d41d2d449593b023e013091b8b105dde9ab2e19c8201a6938e5624b5b052748d9b98ba15b6a");
            result.Add("en-GB", "8eefedecbd3fa6068d784256985cb82d804e5ccded7b91cea48a9e7ff7f919a75907608a160975a95d6ad06502eafec2aed1d34431cccbd693c038ccbdbc3abd");
            result.Add("en-US", "d57a0c58957cd8edfe6aa44965c38221374ddf067015d4f0357d148e1aa45bde8f7af5db3fd48c95d7180edb2ec0982997d5e112c7b5acd28d2d656be3c6f2f8");
            result.Add("en-ZA", "98e917c5f4e20466b18055cfd7ca6428de13468a33e795e9ff21f3877267c0028607c39773f8d21e946d1951fe39bb8fc839457516079c48b2cae7f0132a1e76");
            result.Add("eo", "1342992aa140ed222cc261878ef8a93d1eafc118e33da90f1a12d984ddc62085e1117382664656ea9b9b36be77bae20cfc3ff27bfbb76216de3e12bc139a24f3");
            result.Add("es-AR", "b2415720ce37b9b5c81ebcd01f734bfa9a74baf63052625069a7551809c089d593ce4f11b95b610252e71622c3cac7a15acd5fcd488ecdf6505da5d5b3d58ad2");
            result.Add("es-CL", "6ef1664f946115958da8979d8fd1a742e67c28bc0d198c313774b28a0b148789c9e0ca6327f8447dafa1b779af23e02b8c5072dde8269d2057e54c40c77e2e09");
            result.Add("es-ES", "6792b158ef5ea7d4e1f6531c02569792791528f1f150709ce0869051c2bc84aa91d57b5d13f56b243f3a37c77dc434de61a94290e2f730912e60f6515f465daf");
            result.Add("es-MX", "2d0f0d19e902d342e715c594615b5bbd34b0d8b3997c46442800f0dbefc527205ec040da5220436edf49adf467f993e848696d95c7e847c23a8c0fa0ce7e087b");
            result.Add("et", "91751183c2552e1f503562d4a658a591241deb7f82fe954f288eeabce77c5c62881605aaedc7fe54b364b64128c82e65ddcb59d8b7ccba2199f4e5118c7c33c5");
            result.Add("eu", "7230856ddbbef7a4093447e624046d8179dbecfad117df986f03c1ff6249d9411c66d36227d13daf5f8af94ce7377e6631fad5f446ebff101977ba128c4f22a3");
            result.Add("fa", "0bd0ca10a56defc37e8ba44643eae2ba028f32f51bd000a56163209e9edb99355fef9044d29b567417489fb3a9d2ebd87ee40d416a47414a0dd2a69504a9e141");
            result.Add("ff", "9c113cb96019beff326cb4ed042d34d664c703ad4a2f7dcca5ee525d8397a88ba3c188d2bc83a8eda08e187a896a5d60103f95a870f3aebdcab6fc04fb3717c1");
            result.Add("fi", "d4110beddb3f871834b089cf84260a5039c785bc8a334fc3d78da32623c52306d96b44914a3c45236ca430df3673070512fa5d1ba0718774c27830820e63f04e");
            result.Add("fr", "75457bc9c53caaa3d71d1d298ff6044bb8d4fd9b58b109c0f0ea077af8dfb7bbb148b9bc64dac56e626d7a7f9daa67155f6b3b0cff4d394a472d97939e079b44");
            result.Add("fy-NL", "4cb4f2d0a36d6d1fe794bb903cdbdacc136764f0857a19f393846e6fbaa1d1a12c759fde6a5e4151e533cc2698119adee6ca48d3c8f7de776e267a5abdbcf5fb");
            result.Add("ga-IE", "0668c75a48768966f516d1419a25a9a95283c58e4d485d9f7aff97e67337352714bea8d55245b85800b440e158f832a8e3942b676a85187e13efd1089ed5a234");
            result.Add("gd", "24006db7ff99ac73c03d4d1cf5fdbd656a3c8fb1195c8679c0b9eb48570607e39b72fe8aff35ae6d6705210f2a934f78cf48a19a01a041fad68e5b06fce74dfa");
            result.Add("gl", "0d12e45e3a9532a25d8ee93d5369bf7610a23e5697a220e540cd1037f309afd287f374bea0f9e7d1fc830db9cd1a637c5cb08b56503bfc148f80a8c142a2f46c");
            result.Add("gn", "91e81c8764cb4b3811a675db3e299b4e261c39b980bff6842abe8e0bea3a17b3220b40287ead28a84fd64b4082cfe11c2c47ed436960253bd35d800a32991d41");
            result.Add("gu-IN", "7cf5d97885f19832afd968462573d1c92ef88bffd7dd91976f73149d68679d9761a1969ca2e739602410584bb4504197ab7fbf307e2e4ba08445b408486980bd");
            result.Add("he", "248e81477dfbcb68d81fbebe76906ddb92e77ee0c35a5e66325bd3bd2567046b849ee8daf3a7c59f7a7a88917b07fc4c3ef9d101a99e51e3d9126da8c56c65da");
            result.Add("hi-IN", "55bf15ea9bea9fe1457d553691a73ff3a48e7da670018e2fa8dd17a221caa08f220371550714b05f8349e8a46d1b1f85bf8080245c28a40e36a9d3e3d13a490a");
            result.Add("hr", "7eba35a13c5603a44b0e5518738504b669554ce9435ef3c7c495811a02c73b35b9e5ca32cf5a14020de883a641006431346738f2b35abf7a43af0d269c338647");
            result.Add("hsb", "dd445f9b35735e41f9c6ca547796498fc8662ef661c02b1f06f8f3d68dc1ce28d29b7cdb72b5e0eced7cd0d7dbcbd92b1770aeb3ac9d1d399967568eddafaf16");
            result.Add("hu", "025e7db6d4e21937d806c810f8475ec564c3cb3147742966f88e15b9a554113a00628aba6c2d1cffd7b4fba20ad81401d20ab9d9ad137ca8805c8535fc5588e9");
            result.Add("hy-AM", "39c02e518c890738b8a2d0d9e43cbe6185abfeb705ec34c465b35b015f415ce3cc5ef57be8fb676c4019c65d1214e41f2d8564ccf3cb11cd27a827bb95d2489b");
            result.Add("ia", "ad76466465481ce0efdc47e8ebfd0d3ee3fbf21a05ddb0548819e139b0df434fea964527dba5ee15eb79e1bd379f9590d5fc29fa082d3e988520f76dd5cd1466");
            result.Add("id", "36e531cdc20ae3a30af2deea0057708793a728e0e5299e6c424e75624bc897bd532a51beae644ff98670154261642d0bd9bc28baab2bc3fb1ff5289194c15d5f");
            result.Add("is", "3b51fc15fc59de0f9fcf315953dd1c03c9b94f1d44e010b23b383980681c34d84bf3f0113ac27df8306cc75d46e3d31ebd545c32236377d907a80894bd774894");
            result.Add("it", "356c4a1441892d3951c1855b1e08f5139b9a1615dc562f437d3b7a8bf88a3d581c1ec14874648c4fb404a1ea04190d084e34acadd38743159c1a1f98c9ec9bef");
            result.Add("ja", "7b99aee0da47ff9243008dbd263ee075287b309cdbefd5cd26e38a77add29ba788bd1198e38585ec25025a4244a7609fa29a3e1ed266d11feacacadf32057311");
            result.Add("ka", "385cec99af90e9f28be1556cfcd9aca9bc7fdfd4f6f1782e9fa8b4ee378a283ac5c66a0f0c739fa486fc7bf86ef1169f016be38a93608f5635c39a44527fa3a5");
            result.Add("kab", "5e1886bac4baa628cddf1e42e664bc72c836a5b1bc665d67202db925faf2b93076b37c8fce4a4205d81c4d5ae44eb9da923666661a6e789b3cad7c108e1a6020");
            result.Add("kk", "8db6108916e7cebc62ccc4d0ca95c6c36bfbecd60071836bed9a6116d2530751cbd1b075e31fc156b5c789a2e5444cf74f39163ee7066f9b07053f3e90a2d06f");
            result.Add("km", "89f96d8a88105d0ea77db2c3ace1ab8b9307dad3efa2fea43b0fb3c6e4a184036979736aa3f4762662b1c15c83bed290a4f53b24402fe8b39016126d2e7d4e53");
            result.Add("kn", "97db63f82d1b9b55792d6e9dbff1880736b4b16bccdd3f40e70eab11d259d3ac1c55d85f84485255c0de08a3cec35000c2706c229314f44b86f395c1c66a04ae");
            result.Add("ko", "e6691c4629514720d504bdc7932fc7d08355458ee5a48d076e2bb1fc9a54128d039810f82125e9510276612b51cac641861620a03aedd55a3d94b9d6362f6f06");
            result.Add("lij", "c5a9650c2708d4c62132b60284d8ec160aaca1b1d340bb8290da0246cdfc2889225bd0b6c9c9557dfb0f8930b89a70af76f70359100a654f781792db0a85d4f3");
            result.Add("lt", "515b72317b279b6075c8350b3678e802a3b07eeeebfadb442c499a4dbacaa256457c7dd50495ca3fbc2d533d96add157716dc028bf224c1630d4f37d99833ed6");
            result.Add("lv", "4aa3b25a11f6a85330d435dec42456bd18f942541bc552cbf2e3bd12882cb1637ccb61d50d9db88940f64a548c7cfcda5723b15dda7a3b65efc3ab229198a29c");
            result.Add("mai", "9e25bf51f052494962fa8465fc3dcbc164bab420772d00f35591d808c4dd93c9f49be04808aaa1ea5528b3e77041f91d847d5b2a7287dd694139431dfbd2f703");
            result.Add("mk", "2d0a471651e562fa22bf5312ee261e404f6007ff7958cd1af946cea82388bcf4994ffd38e5a3201315147f321eb4566415dde43795bde8b927b3d565e3115153");
            result.Add("ml", "fe00cbbff5f7ce5dd312f7b61c1cbfeb9d3313a019c70283a9d9e1241bf46f0301803347d9477113773f507a099b60f4d311f22b96056ba4157398b66502a5ae");
            result.Add("mr", "64b5bfe28922bb20d11499dd278ae56ad04c33a8638e3cb09a4d79764fff957daee2b39bc80ef86fce4b5d9f21048ee72172f9361e5ffe528285aabc97854071");
            result.Add("ms", "15f97f3318339f03b5e250a2ac640ba53d7572aced28601a9e4c6724e87a3680ecb38cec0cfd6affd884e404b1b86cd627f098c7ba2a5301f72629dcbd5451e7");
            result.Add("my", "1e62f5f44e94053f006119d1c9b1c3bcda49e09fccf61903b7468b78d9083e02aa81fa28cceebce6b6a80dc11dff38e16a6f4ab19b9f36773be97436cd8c46cf");
            result.Add("nb-NO", "876a93fe51effe4cdc718915014c310e49cc99db3620cb03025a28c0719d1fce4af74a56b8f31f0733cd4b4015ba46e2949969b73f16021a1b6493ed7e963934");
            result.Add("ne-NP", "0f71c8963922f17080fdab3abf717bc911e3b27eb9b1a5889810305a0fbb1ac06856089f9867cc3b00db692cd1043118cd2e1772390406c4f4b3e47a25bbfd7f");
            result.Add("nl", "85d11e563e3d766bafa2ae12316171624c78610e5cbec778f78782deeb5fe141dd23aa6b6a9afdfbb12460e3f36ad5c821e6fdf40aa88a583092b951bea2d8d8");
            result.Add("nn-NO", "66a42265d46a2e1e30c2ab8cf5fd47fcd96fc047ea55edaf482ab897e613a862a8c5eeb3139e245640d498dcb3858bddfee85e56ef0216bdea982ae116e52cff");
            result.Add("oc", "7471a44ed5635c7425e6a15c69815624fb22071de644bd1b297e3923d81b78d34352b3dac2619ea7cf714269d54f828ded277720046e3dba7fba81e022520797");
            result.Add("or", "cf52a2d36bfc49df7facbe72c977ffea4e652fc0f535b316edbb05f1d622c63d31898a15d7bf105a32678ce95e989d291bd87d33b9a356a72a2f9b791cf56afb");
            result.Add("pa-IN", "5b9d4dc0135a7f155bb425f9251ddf355a1b61b2e998fccf003ecc601146640d5f65d6f3fb5556e3ec4d71a5d8b7e959427b98990a7133559c5324b7f203648f");
            result.Add("pl", "a43eb3e3746ba609832acda8c19968587e3d6900e3e5bc04364302074f231c59a884346beb6d3ee4fda1022208b5747c56119f6a53b0e07a586b48fe2341483b");
            result.Add("pt-BR", "a46b5089b859a2d8205f347f43f9f77390b039f071cf72da043b087491ec4b2e8143ae80c304370761cc2656e1107af9ef8230e3974614e81524fc5f6ab4c254");
            result.Add("pt-PT", "b73449d7fa6a51808ef74eaffa2580d385ac5aad2e6ea2bee2b955d00a9dea7804afb565bd9ecbc3661b2a886e51c16829edf4ab7d4104c4378696903abc1527");
            result.Add("rm", "8583f6fc952ddf2f2f5b06aec51cef9ea2b0fbf22acfb53d7a2c6f1e312815386c9da435d456151169dd16e04b54e953ca1f4a069c3e247792bb87e41e7cb5b2");
            result.Add("ro", "c3419c12c0f3551c6e4e11d73cf899b4165931d1a2bd5ffe576609637cdcaaef0311de4ed18c4379e8e7e177311d6c7278b9d9b02872e6b3ef9ba0dca335282a");
            result.Add("ru", "84cca2e4c28b9b7af201792c79c6faf7f61e8c97c09ad0bc8adf1e36a3ae8f5bd3a3bfc0be41aeca8afb32ad191c0ce4b88a1ce4ff3199573dac89a2ee58bc8e");
            result.Add("si", "d37c03c26528d4fc962d8d3ae566e8e832db68241f700b8d1dcb5d25eee83318c605c6bf5d3fe0d63eeb54f69489055abbd6c43d1fd0366f6dd5a5eb2869f9d2");
            result.Add("sk", "0a58379de43b7ac81c42c1dd2ca4a58968fb0c08d5189ff55ed71466f7c91ee3ea36f098d127510686b957bad7b934088b161eca63605d325b75f757f4de6652");
            result.Add("sl", "000001ca5a53656ed68f4cf929255fef9dedbb371891409c91a3fd11ce6c8a040f6599f1a028e0efba567b007abc9634b6b77c02b6fe9d7ef9fd952ba87390ae");
            result.Add("son", "41b01b2a19c8824b7542e25d3bf70b9d5988de62aea07b547a0539382aa45cfb264748e137f61ac43b7f01bf59371a03272de67386cf930073a8b4c7e2e0d474");
            result.Add("sq", "17d25504271bfa04a95cd2105f58abb0b4a48ca5d9495c1d8dfeb470a87d6a9292759bd18268e5d944e6975759f16d59c9e0e356474ff6c485eda0122e4b667d");
            result.Add("sr", "b2c3996b5f23b68ae1538049d50c52c123c64d1ab9ba4e92c21e230f3fce1b4bf3f0779ffd4a912f4fc7f4e93d6248d412672ab9e0bbe9dd3041b0b8f30466c5");
            result.Add("sv-SE", "92b07246942d82f83ba428422ff21c7aeeca6bd5cbc8d7f878e452ddf5571c827cd4575711dc3dbadbed09f0415784f1424df24f30dcc578923d8266c85b6722");
            result.Add("ta", "37eac5bd4e19acd3d364e7432238fa89546510bdb3cc5640592059d6ff6c274131b78e4d91f58c005e4846b984e5e80817c42d94fcf185dbda60f4b668a57c13");
            result.Add("te", "eef50287b39241cba6f56946c843e37b020db5178158dfa6d30171bc62a1974933bd4923f3bb59db3de7940c06bc079ff42725f116f07a0cda08b624deda65e0");
            result.Add("th", "d76caebab511ffc227f8fc73309b6a8ab3ddec9906d420577973a0ca22c1c1ab4382c52bf639eae91bf8657b486a944ab36bac2272b5a0bf8c74543e3c725ec1");
            result.Add("tr", "16e6ba7ee452dff50fd8f76512bd73164904a66702da3a75cd135198cfe49ead8e5a83eb2f508ac4d28dd63503e881f8556101fa01f6426abea07ba738b7515a");
            result.Add("uk", "3973295007dc69a0f6fb48e3c0bfcd377adfce59bfee7163df3d13d1b2a7ea2af66edf95256159af44729a8783752f4b45cc5b47d931367bd7820ae099904850");
            result.Add("ur", "058ad34571d55dba53c952649c0cdbfb18f1ae22391804d3fd20e0bfa6673b8cb28673eadca6de34e989962667decdc9480db50816734e4a001c9c466204b0e7");
            result.Add("uz", "ba7147661f12cf381aa1b9ffaf8e434072828ef4c5a72eac3486efd58a11c83af14b5fdb95fc9c78a6729e7f8bd9cedfa34085d5219a8fd20bd2872cdc349fb6");
            result.Add("vi", "0efd0b7e356c4d3b0d1c501d22a03f290490aac69a5fb04dfa17b95eaad8620f69ce4d3e309feead7696ba4489a396ab41fd931c8a2d87bc22972d61d79538bf");
            result.Add("xh", "2b38fc364be6acb6d0a11363ccdf93036642678f680fded68e87d721bc775677b5892d5f53052708ce3d2cab923043e8a2478034c10ceb3d50efc2b5efb0b42f");
            result.Add("zh-CN", "e89d3e06fdd8bf8e72e6825fd627c6223732f4aceba386eb58d1a418292a39fd3f8272896451332b05a560211833d66d7ca22ae4b3a128a5a21915f2c71b8114");
            result.Add("zh-TW", "0e2b0b1933a5b0fe10eb0bfd176540898ba1a8d6e4ea0c5414bd9724cee1a9900efa1179b85ca76a4ace187129bf30fd33da3d8918a1211f086ce9892891c0b7");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/65.0b4/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "2711e1dd0327e5def58c6c7e287e83e2167aea7f27f6462d6c07092be90cd0aa50ba9df0e34938afd5b3ebe2aad28a764df5c9e0e433a3385e13e2f6baca5911");
            result.Add("af", "8bdff746c47326a592529f2ee665dd4d9b9f5a7894ba792fcd6e1ed0e189c73e617e6d25387977abd33c46a4a3e8ea5cf19abff3f4ee7a3d0d4742b4c879a8b9");
            result.Add("an", "d9e3573e039e9a39d09d6116a356bb19e094dde9eb3d02d7ccf8ced0432d3f99fb6227310d7371dccc41ebcf28ec8b485783b51dfb288ee783724b40acdd9b29");
            result.Add("ar", "468a1b1320cb75e41fbaa86886595c7ef4e6488145e5d0f76892274314fa286a78ce7dea81ed6e934d7a9ea7978e5cf4b1deec1a4023f40f4506f4f4a3f2dc04");
            result.Add("as", "739f02f15cb0794c7265ba5027065cf5e7d2f50a7738198c3312c36e3d983e715c9ec3f1062ab7a58c131d4e85ce5f148292723c0c37a62e04c9cd39529164c3");
            result.Add("ast", "0626058cb5b56fda35ceda41b2820ee559c057420756c64f4a28c568ff0ed7d3b5e42963401dc96a0cbecf07874c5d8181caef53c492126a85ba97a931f9ddff");
            result.Add("az", "da3457088ed8226942daddae4fc96b66e9439e0fe019b00f6d9570e91f99989391ca48516e63f4910a3ae3b07fbd02874a8667570f564ad836d0a5ded0cbc2bb");
            result.Add("be", "c3a440f07fe2c90a7172d310b9840f0d11428e55dcfe7f44c7f131b83b2f8ff3eeb9eb1f19e17a1fca70908012e2e42067a0312dcf5462c33246976364105d9a");
            result.Add("bg", "6cbdfedfc8e2a8d4072c1eb9df0c34fbfa6d16212c635433ec90d2ad7bce15725432d0ab8a59a3d296b4c9a2290208fd538492f08fe42d11f862e5f313907740");
            result.Add("bn-BD", "fbb7e58784fecf3500784e4ecfe68aa4222f79c354fd265d039ea7669f63f6ca125df7a5a679b300b4b2f19244e3a0a4a8843ffd27814f2fba5b7c9e626fb70f");
            result.Add("bn-IN", "57807766e1a5be5d3449c6870283bfe83787524287261135f11466fd44851ab2339ee651e68f6c146b4d99d4feebce96e02918e5faa0e3c08b11ff0935f29295");
            result.Add("br", "7a6bafe4ddd61d9b05f545622179e5366dd045390b3172e7b163ba8660f508e89abba1a12a5eaa5e3f86c91cababbd8435e5e85f4f3d58cdf6094e11c470bae7");
            result.Add("bs", "39794e6ae6baa86a0f27b04c843e358e2018319d1a6b9e1f3d42e5d196fd3eb1e27bc41e4297c81a879f632710d2e9def759c5404e7ba861e116db0bf07caf84");
            result.Add("ca", "7e8d90d215f2aedb7a39aa1f1041dc5d8182d9b9e51550bdf3adf4e0945e2fea76483a655b7e18c8a1f66c768022c6e368da0dbdeec014e9f0fcb8d30bba6295");
            result.Add("cak", "3a281148908173ef08b95ce86c54fd8fd72b9d4ba064e50d17ae935acd18b3bd2be10624be019394f457bc767ee2fb4250688601093523976e4742da3e662d76");
            result.Add("cs", "e3d81aa8d560baf6049bf7e2fa9b8a326deb6c49805b263629a6e3b104ba7b78934907e0da35914c0b7d37a593d3336244fc3e7101606314bb708ca2f404ab1b");
            result.Add("cy", "b538af7e46aeedad00509ac84c4b0255e99d2221c6e307561af763dfd46ea9074b9b78d50fc2b1a55046dc959b601d513a785f8e977da6aa2071e92ddd7da1b5");
            result.Add("da", "cf64a6f1c1629c0f37f7c74c91891a2b85bd7e0fa6a8298305610bd7048b946eb22e3676bd3a0817e5528d36a2e94e0c822145e878ccea2999ee915bf2e1e8ed");
            result.Add("de", "2b04a5e74153e1af2c7f5f480dabdf26404e9329bcadd828abe17dba5efd565d1b1181ffd73b960f22c8e81f1b132c85f26056dab0cc9f08efec0fffa9d33c7c");
            result.Add("dsb", "82e35d51808094298871cc8d99bba89c2a1e1125031a0ca16744d76d4d933d95d2ac1733b35d67947ff968407a0864a6a7f8b18f974c2a56174087291ef644ef");
            result.Add("el", "9183854e3a863f72f3ada7497f8163240a8da0423a8c4508eb048507e05e15329da3a7e0d63f24e25ff684f6c43db322c9043cdfd5543a931e3280b3e985cded");
            result.Add("en-CA", "01310e6faf342ebf919ce197d59acc63e4d853980beff692f11e12f86a70e9a93d3ea25d4b1fc2ec1fac2f93d2ae0ead5b2c1111db4ead23dc5de3739d47e332");
            result.Add("en-GB", "0fe167645d84f7bdbb60a7204a96f6a1ed75a205ddddb37ea65c074bf1479e229ea5695de966cae127f1def829d9566dae3cae3d8332959fdca38adacf950609");
            result.Add("en-US", "a7002daaed247daa924c7b657340e679dfda32af4d7357414d653e66ea05fa9b5f29847e9f87dfbba2d9a9a258d54931f397e4c83e7dfc586ad7cf1e66608003");
            result.Add("en-ZA", "f89fa4fed2ac456221667d7d8b685ecb22659687a20af58e74fed78e01578fa25ea2bc1b11d539178f71d5484b729609fa4cca10eb4c53240cd011b1b09a7810");
            result.Add("eo", "2e977c58f4022b87c116db58ad9edd8efed9b429a962e6e9a341a971d589aeb9c05b559fec2cc204b52f83b40dba7bf2567cc5b294d587330736315576204667");
            result.Add("es-AR", "3740bcf55d37ba051d0174420fed0b5224de6b83b194bd37e311286d464d5b18e64d704690faebbc36d4d03a70c473dba4de81297e8abaae64b2641a05b05cba");
            result.Add("es-CL", "84fc53a984b2c4491a1e3854825ad4489bbf697cd13e3948784ab599863e48ca5089b5fac71a97771bbb6ddfbb05f663f62e678b241135d372b4b5fd702685aa");
            result.Add("es-ES", "4505af98f7586e693d5df4013529d2e56c281fafbf938de7eacbaf15134009c90927d986fe416a822df5a1f0a010faffd1ae83121a754cc0b28edf85c4b4cfc5");
            result.Add("es-MX", "3a8adaeb906db0f3ae7928a649111f7132f2639188edcc087fcbc61e1a0a1772c8f747de6281cc02e5199dfab9d6e0604947b13b1e3ef9910435300a59d21418");
            result.Add("et", "beb645594493b39289fc7c4ac83f4d9f9d25cfe65141a77600dad5e8b48aa8314c978a54d0c9342aeeea56682a14770b0a2d98ff38f4e1e2b12c0935c9213519");
            result.Add("eu", "761734bdfd907f08aed55098f9fe77169c2e3d92ebe4ca160da3eff2cc32fe34f1f321c8407bd324805e6a9f659860307040179315637531b7c9113465372fe2");
            result.Add("fa", "dc132e070d1283262d49dffa5228dcd33154b7205fb7b40385686fa0a53e054dcc2d237dcd6c09506b185ca98ac6dadacb2fe608b15f4c8a0e085f5fec34d328");
            result.Add("ff", "5fac239cd85bd214eb21010398e850d2d70d8e2a48036244bf5721e4d0dec06e35a6457122fbc258a292722e264158dafcff00e245f361a692c8f6ac480d428d");
            result.Add("fi", "c47241a3aa62ec138bad04b45797308e9481659ece65c401bb0b4cfa5a179f695fd74e8fffc04a4761cc936d5ecf6ffa5151eed0a8c0a09cb2ef0319f43d2e5b");
            result.Add("fr", "ed6d3fe794c94e75264da8718fa91723c572a4f81388a5f55735dc2659e7b08fd6aa133a4fee92c824b29d546b3e9a96fe86ac2df561488462fd399bd957e963");
            result.Add("fy-NL", "34adf67f45a60b709a61a26a5d1d5ec75968101888f9407305a2b99691264420a0f5c30a5b792e15aa1e1dda2419bc2966ebaf2f3f09dd16dd503312b791545b");
            result.Add("ga-IE", "2cfe7bfb3f481dfa76b5afc2634a4763375e6c4bb35e886c3d9a32b68dfe6de3d2b8c5161a615aee46f297e347506af27567d91ffe63d3324cb5de2b63715e76");
            result.Add("gd", "b73fa8f184c22830a47035479812bdd5c98410b1850679e7035d6f3a887781fc767d980a0d044b5494721656152784548d2576e69e148f8fc1b7423115245c22");
            result.Add("gl", "c6f2541df7ba6ae7a9de36083d8abecc6681c1b224096cf082542aad16671ea094d7d5f8cc0bb9617d58e5b0671e1cc1142014b048a6858c6cde98ce4719436b");
            result.Add("gn", "6c177c32e2851f751f519bf9aca2dca5eeb15e7e30241e61f4e6e20411c76a945e343a3a136fb497a7feb55d61f8ece7a893d53cc7e7659bbd20ca41b240df95");
            result.Add("gu-IN", "857bbc0bef3e87f926dde7d38f24b4151014f2cd77a0d42907da25c7fba16097730e367344743871427749703bb5a58425021cc2394495a612b5ec633517caf5");
            result.Add("he", "7b3e0308209678a0740f641eccf13ebc50ea606f66627fbeeca690ae8e2b21ce9329148fd233a849604153ada2afdcf9babfdd83de45717ae2afcb9110126af3");
            result.Add("hi-IN", "a9afec07038ac11c42a385bc12ef0d92c4edf700b8cf62a50643f79a2856d5102ce9a55cb76652073361143d7e5b5ca2ab263a0ec7cbf5dbdf07118f220d08fb");
            result.Add("hr", "119c3dcbaaa7b0a155203aa736a59a7607d1153f113fe867c489b6f8b7eab0cccaeed89771337895fa1fd7def137c2139d1d162d9b3d4c42ea6b36b4baaf9754");
            result.Add("hsb", "59b7fac4b77d2bcfc9c3b4be07e6ea2d3fa6d9a1cd12bc90e675c44b51a614db4db6fb1df1d81f8ac703e4303827badf559c3c67c1377c82f2870cac7864f1bf");
            result.Add("hu", "a30336e94ac9661535e9b81a609af6441aefba009fd7064e5d3959c44fcd47c915b0afabb9c422d1969fb8092b7b078e2da6e134b0e7b40b09f5fc9e3e921047");
            result.Add("hy-AM", "24ba1702a3ea85783e944e6eee20840d31f9aed9c9b46a4b87a07fd35a764d94efa1d46d9b0f78b59d7def5ff6ce9bd1ea0ab185065d2890ec855444c54bd3ed");
            result.Add("ia", "f5698b0696d8687fe5d29a9d015522d825ea4d331dae42af8f67038a191e1d19f5e951ab621ca46ae3a5365d0ceeedb8469bddc0436598091460ab771522fe70");
            result.Add("id", "c9c7a33ee87a6939bd92a1bfeea62e5b71f70974245eb2544b7bd96ec6f99607d3b98c16a16a43f9745b8eaa437c3db8b04a52498015ef3d0ada5556973ed175");
            result.Add("is", "2991f7f1c72a9505463ec15b00262826d0ab408cfb77aa1f6152af0f2d19cd742ad3dd60bae8a191313c61ff2e84e90380f586b842ba2e16aa8ac8b0cdd16003");
            result.Add("it", "29b481e57d3868d55c96e6868ec1c92268f441f801a109a647053cfa2524ee1e4995ae54121aefd16f00c6bbaac930714ce39e578c9cd12a93c3ba0af2c1fb68");
            result.Add("ja", "6e93af80da9a568aba8d60dcb596cca26de8e0d09f62f0f409cfeecb9725ee7fa04908290ed09e0ab9448e6abbaa4ebea62d7c106d835619063e7f533ef76bb7");
            result.Add("ka", "fca4e5c5e7d688da30f1fe59195121d2712591bcf140ff0681c4f5b7c36c74c5711bdabd348c986eebc14983bb0d301f9f92c608a326c379180c4b008c9a9a0c");
            result.Add("kab", "cd33774c774ce9d258065ddb178f54d52b7e72b07363275acc2b4828bd6f49be55093de60f7777448ace0ef5ad84e529814049daec80221f09952dded42096c6");
            result.Add("kk", "abbf23ed43e161508ba0d110d913b53f1893746448ed67edef0726764d92bba4d631e49b255651ac5f3eddfd43e0ba05551c5b7dc0e4232809e83abe748a6fdc");
            result.Add("km", "dd17481c8ab2b945131e5fa92a2a388363949804374874fc01534ff61d552761a38b73a9c3f68af9bc9e28f477ebffcb1498df5358bd4e02eae08a7c0b283538");
            result.Add("kn", "54582cf5e75ea638ac0faa3adeed70c3571cc7ecd77193cea72f8038de7508fac0e9b6f188cb4aee71685ab158e765be0400ad25c9a0acbc2fafa93ff1faf659");
            result.Add("ko", "887011fec5ac04524542e1183b374600f5d115fdc1080816c379b6b00578343ca4e9c6990dc76fa53d2273d71d6df4823e124d26b97db39821f3411faf219ded");
            result.Add("lij", "296b77002ea9a157049d24d144ad1f9b2b957089e9c47fc6d51fc0c1ed6c07cbeac98004ac77aecf162e717caf16f372ca0a1ce9801e597b598d80c662b319b6");
            result.Add("lt", "7a0e23a5a3ec2df2c947d040eb0fb78c273f8eb551e2808659bd86adeef62795090451606a3a9ac6b1128760b7ac75cdf01477f7e08a6da4e1f854fb6d448609");
            result.Add("lv", "3ea9dcf7920378f401a7a198b4a7a559d58f0d750063036795a397c4070ace513183e35def559604fb16fec261361502b01041725c4554fd1a062db425e2ad05");
            result.Add("mai", "42ac39cbbc7a3f57f6dd096a11e99c2747e333fe19a88322df99e62066e3f40a34fe27fa103fb677b7a8c77daa95803da858454312d0380f9c68acdb945a2bc9");
            result.Add("mk", "9504bcc9d3c76d6d318e57e75f77bca1a4257d66aa2607eee3802177ca2f6ff6a03d1406700a72d73d8ee935696867d03b79e29159ea968020b4dcadf48d76b8");
            result.Add("ml", "18c7b7536086c743c960ca20a0a29e9f2ef8fd76375dac52174fc5f71bb231551c91a7a0692dc46bf37eca5976ee74b0094a4dae53c38d2d4800be4ba6ba2ad2");
            result.Add("mr", "55cf81a4cabc0000a58569dd5dfcc384acb20fcb605f86c6f3ff7d35abf5ace11aeabacbd681914a7f24f5d49c004472bf6b479bdca7893669db238ff37b5f2c");
            result.Add("ms", "5fafee4a586cde21293ad27c9b61a19f3964567242580a33dbca4167188a3a4c9b8776587817e00fc886d70a64a70e624df07f8feb5cb75a8da365f2f8c2f679");
            result.Add("my", "4573fca5854cb58dcb438110f7dd68903779494e3079dd72a84f3cc749a57b6b47d6c68ac2c6004ff59c3c539523e700f8d90653dabbe646bde44f25926598dd");
            result.Add("nb-NO", "d960e3eb40b3a782379c2c6a2ae929f6863cc2c7bcd52566618bca390808487d465c1192dfd42f4cc9887c113a1b9b7d30a6f89e8b91f90ab6396dbded15bc5e");
            result.Add("ne-NP", "69b7e63742decd1e8663a21f6e3dc49e8efd8ef5c41113739ea83d6882086f0120a0162af4bd695e05010c6ca99b010701c91d4810cf15dc058be4614553e804");
            result.Add("nl", "625b4377737473ddf895367971b7645520ef728dd82d91a6d2f8e7c2c089b71759d7fbbbbb56ce76879eb893adbce702bc86bd5e8b7398b4f625f7d748880d45");
            result.Add("nn-NO", "55b08fc990fc7c8c1f61fa749f56ac6d26f5018156376476dffcf172885b64f1d00d1c6712ffa5f7b9c3a423f42163dced52845c7d43e4c6a3b26fd548c106ab");
            result.Add("oc", "18af72b6a60a269ac623a6fa5e437b8c3e303ea4ae49df2b720c875973a232fd5e4724f5eba4431a7abe8f8617e77221d3974d3ff65cdef6ec29054daae3116b");
            result.Add("or", "14a6e515f42f7eb61c9af18fd6ee8c4dece341d480dc22c88bf50350f7e8594f611f024bb3ca97b96ef3b98453f6f20bc8f59f76c790e06247b72257bea14fc5");
            result.Add("pa-IN", "979e306c3e48ef50a6a6272dcf4f83811916165c7875db20c086f687101cfd28fda1a7e189f16e2e59651610b54bd12dcd90715e88374ced986dd1b334b71ceb");
            result.Add("pl", "c72070ceb440ce6e8086b6e376d31e03956067a37170bd24d871a4b16413810fd6544863acdd6e915dc998afab3e0ee413e0106eda6d9bb982ae3c4e968eddf2");
            result.Add("pt-BR", "068e3bab3ae1e542920abbb50643ed0f127c8c760a2e3c22b4b4b531392e85548ac13fdbc39b27bbeb6ebdf0e92cd868f975313c1252fa237ae4e02051f4c7a2");
            result.Add("pt-PT", "57a0963dcccac2b2dfbf3a7d3e40e632a566c9d5573e345060007a22b8ec57dfc874215778784f225e6e8a62f9668a142bd17cbce1de657bafa0d1d595554814");
            result.Add("rm", "9f2fc56a96efd6e7d56455bbdc9a78403b9f012957f2dc57fa0361c2f660c12dd053e2f1c3c4e609be374ddbca3538d40ecd95abdeb4b31744e09dd3bfebbead");
            result.Add("ro", "b6e2374f9eb2c5d44d943af026518db0ce7afbce351f45560788572f89c3146f152ca103890eeac0cc159f4c0dcf85ab0a7ec61a7468f4234308942591439000");
            result.Add("ru", "8fc6a2e3b16853b1730b2563a11b9b0f6e8de5debd108cabe19ac2bcc69196bd8d3753c27caa0df43eb2f90ede262c6cffda252234bd82e7471f2317990557f1");
            result.Add("si", "f72310265d9a6e9bfc6a222dcf1748932f93a90e8bb1715eee80c75fc726ef6084c4c0ce83adca3a2527d62992c527a6a46efbeb129e1da9cd81aba38fc278ce");
            result.Add("sk", "1a501341ba921cf413efd76ce0234b9d78b2de900b97271f8bacefbf59a961026116bfe49b29cdf6de23c5a119bd4799973b84dbefe47c055cc9ee85578fc1a9");
            result.Add("sl", "35fee5859a70a2f718c4fc75fa3551c68f1788ae95b60d86b107c6f12e9478c01b9c8eb936ffb0a7bccd4ad98b3aa52224000a42114787def2d143e8cfb2fa7c");
            result.Add("son", "38749f3cd0b6ce85d9c6edbf5f6121f289bb4b442b39b69a3fde4c71eb23f6a647f6ce4ebfd253dfcf3bdc5bb33dfa53f2a6b869c7e678fc5cd2a42dfe3c89df");
            result.Add("sq", "68e2dd08fd01d6ed04ab7a2c414febb13c8b963829926a3dd56853a2ad20a8af2f62bd0eaf8abfcd725de93bf089e1ca8880238f283860dd793ef2e9443ebd04");
            result.Add("sr", "66df9a067325dbdfa9c4faa784e12b7d13d4e0ab8620f9b972357979c4759e963847487b8e8b98491b4fcf25b2c179914991b8244c8905d6c86275d264115377");
            result.Add("sv-SE", "9e6933e13a304959563a8eddf025ea0b4b55e83193d97e248a5770874e1b805af64a9627fbf80dd5cae8e32d677c788b056a3e4f919a1d81dcbff124d5ea0f1d");
            result.Add("ta", "a021ef5a8446294f695f515353a5339b42520b13cc7f31be51a89c4940c7e43f5ae132853cbaf9dba30fe8d3542b2938c9718975b01e4cd981534178f50b9a66");
            result.Add("te", "639c06dfd59a882ed4d850fcbf32481875e37d4893c6fec7da3b2061bcfe8411f01a0327e076a852484352f1b2a2489609e2ae572b04cbb5ba32180cfa3b58d8");
            result.Add("th", "d6c89730e3db306a74bf2df7db4dd4ae81646b81f40f84cb635502fc854154f2410fbcede2fc7b1e0a63d54a1f665c2cc7621ee29fcdd6a41ed4257338933c77");
            result.Add("tr", "76e3686d7acb26185584396c9311cf146fb55da9afbe62a4cac9c782969aeedf065cf82fa113d2f25f7ba6ca62bdbd052fba41055c3bf66465fe54a08a0b5450");
            result.Add("uk", "b716b7791a5b842261f6499f4c38c081920d7bee5026e191597e8bbf70c921dedcd1a5525a21c4607e603de9b91264dba1573f85f7f4e9e9f009e70f128d0042");
            result.Add("ur", "d6e9fd56c153b8126f9b66f97bc6aaa99f2fe16dfe5352e378a9a5bbb509a44fdeca8e9805a288cec6dab8a88239c0e84f38989fb12320a13641e66f29f0f317");
            result.Add("uz", "79b5df2c946d3d31fb44bf6547e34673e7eccbecf6bb2a2266aee0d3c44186d760af54aa18fec640319e3190d43c4ffd8c786a4b5f9e036ba8a3f3053b6f1bfd");
            result.Add("vi", "686ea413494c05c0d6cb1f4d7008a6f20405f1c9af47dc1fb6bd84fe6f986cda9d1f6f7682ce88bb99218af4cc67b380fb8e6e92917a256754a823602b61b323");
            result.Add("xh", "4ad3cd195b74a8aa93046be9912985478f7e6fbd7848922e9624c5c4c67eaaf02066e7fc02cfbbef373bcdcaeff34ccff74aeb8ac4c9383167b7d2a3c95d2ffd");
            result.Add("zh-CN", "dbda4b6869996f7673e23ec144a12aa3fde4980d84ba80957a5bc4158a8d020697c717a5c98f5cca24eb1baa438c8575c85d1670049e239035ec94f6adb5f819");
            result.Add("zh-TW", "a399483ef883ef523a9407b9b4d71116fd7d5186c425527d57233a0d3780adb84a9f210ac4c1e7c0c5fd478d2029e3da6592dbdc8ce9385da6971c89565b2c7a");

            return result;
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[versions.Count - 1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
                        if (newerVersion == currentVersion)
                        {
                            checksumsText = sha512SumsContent;
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.Warn("Exception occurred while checking for newer"
                            + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                        return null;
                    }
                    client.Dispose();
                } // using
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }
            }
        }

        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
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
        /// the application cannot be update while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
