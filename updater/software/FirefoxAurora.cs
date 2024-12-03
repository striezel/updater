/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "134.0b4";


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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "cd8b41f1a642ef9dd218a14383e681cb531266aa6e077a2c916dda2983c49748a2344b64b05bd36534e79fe011c0f23438b68e114ec9ee2d09df2675667a92fd" },
                { "af", "db4c38487319386678274659024ad8ad501f047e4df824c0146373a972118110029bb8679e425827325c1e4e568046c0f47bf32d07bce0244bfead252c37560d" },
                { "an", "22a1b2e1784207b289b25ed385bda83770b97f24ea8f413d38c27a861b52c399fec1f2715c84851e94d9cda0cf9753e9dc43744cdd8e5db894c44510cb0ad1fd" },
                { "ar", "22872aaf182a86d0db0681cb3e0f6e1df5b253b34f0335bc2703ed8c54a061639fd2141838fed3ecd7e331cb2834c54a4e2328da97b372b69d4b68023143dd05" },
                { "ast", "826429b2d92a1a111d5300483c5fe7c16ec591c1cc145045e841c2cc56c0e61f9fb137480b5cb8d4ce9ce1ca2278bd516ec16ec2d2dae9c8e24a3001ea3b77d2" },
                { "az", "2c27a6c05ccef56ed2eae6e99a3dc30d9e70cfbaae7fc73eb5df955bf7f4a33b5c53a0347e93354a7ed41e0f5b8286db2b0cfd353c6486e810c288ef763f0a36" },
                { "be", "dccfc6cba4012691efb0a3eb4f6dbe18ea1a38dd246e0ac7211a27dd4b8ed2d455d1569b426bd8a704505a805ed381f81f00854cb2df7a8355e7734aaa3aec98" },
                { "bg", "a23cdabb5f0001ff128d8529b387e5d557395154fc0516906742028071f8753dfbd62f49ce1a50368cddb9acd228e8c5e0f14127caa220fe728dc49dde82c848" },
                { "bn", "338796dc617d809ec72cc346f53b621580de72dfac70262ca913dfcdc69252646bebcea32bb1e388efa9955587b828c9625125aee86f7e7fffc0f89a90ce5758" },
                { "br", "b32400c0a64499e73d8bfd09490bedc174b4e5a09fa4a5797a24306dded4092207cb50e487ab89cc7c6a5cf5250e0694a93acb383be554dbfc1341f8067feca4" },
                { "bs", "d360ca69cf9fd3e5317fac1d041339e77aa9884a22e7698812c5e187c7123721c2deca94d13f7ec9411e798af4ef6bcf34197508b7d585e7e288c2ba5c5678f1" },
                { "ca", "0a4615eea2c424a1c120e606266fbb4b1ab7eb26084a9c2aa0b849806cef4db9f69c7ed4b33a8a6e41e86a0172cad4f09ae986142559981fbb499e33bd9edf3e" },
                { "cak", "85e74b37df523e64c9fd8fddefc69571af1724e5d776e9ed15d8e6e444a918ccdee3bf0fe1d2104017bfbb08240e5f9a3370a29ce2f9a7c1a310d6b05de6fa98" },
                { "cs", "89ec3c1784c336c203118faac107b9040e068cc58cbcc54eba10f8068d5436dddd6b3a06144c79d9365cf0ee9426f9120f8636c253c2af36bd25818bb04cebe0" },
                { "cy", "d61b445434adef2cb48b0700d15ffd69df229daede1f049abb4bcbe632f2e9a3f5ed8137e46a2d7131ffbdf544f5c081bca620f77b72221a84fc3f2b0ee31bb5" },
                { "da", "0d77da64ca82e5cb48bb82ad394ae52b194f2f1b1d36decf3206ebfc0a3f597ff14021a2cdfdbf696241fd237b754dfb8329e6c6bc0ac3e4f211e679304f58d0" },
                { "de", "e6236bbbe99bd72c091caa741b5324099f74055cf701949067eedf351fee04776f00b8f71f38131357b05b70041ce9594843181694611b38f2f29fbb0258ffa2" },
                { "dsb", "4589b9e4056c340e778cf7f751853f3cd7d4b9cfa5d66b49977b346c50db76c9a97d0b4c0bf37c7427bf05f8e26005bb5b170ed7fff3ded5c25a888dc10a4860" },
                { "el", "e4ca9361517dc19b132baacb60a7385858c51bafb8b84534c6677845e1ec5c1034a7f4f51b19aa9743e538d7cd465d824219fe0d83a6646dbf4845d9a8e83ea3" },
                { "en-CA", "3cca59b02a327cc4b3bcdd3858ba551996fbeb78fcbebf484e63a08a067927b8d1214e6fd01dd33e7a677cc210c02ee108e45cc2fc4e84dfcd13593760f6a64b" },
                { "en-GB", "1dedc15cb90a0a83ae75d1afe3aea8ed978f8dba71143dea9159eaef04d6069b8fba3d2a1acd865f5110844dc11c73c9897c824d5abdf5c783fd9d8745a9986f" },
                { "en-US", "e5c45ba28e803a378b1cfe3bba2789b911ecb0aa2af0dcaa84e92c77430adfffa6a82d4e17e7a3fd9e5ed6b6610c3366b24d3d22a74a62a377f867344d3c9260" },
                { "eo", "16dd3548edab50c1be6642b0aca5750c48fa33e5856d1e7be86026220dd8c4fecc47540523b3c240d4104f705554f1046892b86a29bde230cc4544009ca3ad19" },
                { "es-AR", "0071f680ce89f9780ad7dd0afca86e98ef6bd8fb7df4d66147bf08f3d3d1ac1853905e40a20046a4d9ef37ab830ca18f70c2e8f49034547429b9350c10fd8964" },
                { "es-CL", "82daa1d5de1fcd0739cd2f01779ea649c351cec04f446f52e51488a05104a1169d8dadab3610f2cd67ffe2da8e747e1c0cbffe4a9e5bcead8ef4d458ce8db6e3" },
                { "es-ES", "f93b24a6b5257c82a7f910170f8f369509ac82f0a92d3786993239e350d71787bfe1d8b6118583015b5db39a1744a8aaae0088db453cb32fcf1911a87833e4ec" },
                { "es-MX", "dfc9b81159b311e582a24a1962c660cb31e83809a03d52a5da48d4514e9ac66d010e5d893ea00a5d080e94b14fc8e53b104e0dfd790dec5b5805f7e60bc77aca" },
                { "et", "f99a4b6a17e786c4f1d0f06673f9f94bddcf1ede3d774f9aa1d013698618bfa4fc0fad1b37c567d34ed507f6810053890cbc47a2e1aa1b2b383c570378f60507" },
                { "eu", "1b8e260b0854f501d6552914c7bb8da515c5f2291f3fff162e7808328b23169f4967b1f362fe91a6bda94c729f59b705b23cb5eeff18927d88025b9a30cd182a" },
                { "fa", "3304ccecc584dde28e1efef02ca3a923c292f5b1da4b29f969499a272adf9b8ad03ae8f52aa71f3ea5491647e3069e9a63e7e1b46bad3a938c03576fbcaf461a" },
                { "ff", "9b827a031a7a845c487e12825da7f09950ef8ea5b775fb66099d12225f44a324beddc8468ccb01fc30af52500457c7c395f3a2ea125adf984914650c1441bd2b" },
                { "fi", "5299a686f202c257b080f1238d133fb71748aef374f17ea7b55353b197dd90314445676ecb576b8c70962731b509e821ba225b937e1d9ef07189c881d6408931" },
                { "fr", "699cecea54a6a7886677a7f94c63fec3295ff7fe13f742f114ad6b0a667f334938ec0c63c184ca0635bf4b0b53c6e3f4f15fc308e9f18e1246dc0568f3baa3a3" },
                { "fur", "d28250de04711ff9ecd2ac399e905e4ebdaad2a2af2d2d5ef418d160de027ede25fea601892147c4720dce8fa454c920b0de38da173728d2e692b23411f1867c" },
                { "fy-NL", "87f8c189286dfc6cce7ac53ad60257091ba975e9ec1993aa5af509fa81e8eb22d29fc54d182bb5fca69086812ea3f63548143c425473a831c202bf33413ec26f" },
                { "ga-IE", "76624810caf36453e6d2581f74a4f73a2387cae4474d6fa4066cce2e0b10691f5d2c28149ca2390fbcf3d21d6426d70ef68650664fedd0e75caf1e5c8c3624ed" },
                { "gd", "cb871f5fe2e168d705abd67568af59882eb4702575e362e6012fb76683a7632b409087ca91a830c290e76b750f6a47033e368f0ea4915d75132c69b463543f36" },
                { "gl", "fbde511ef32c7cc7ddbeaa5aef468d589953d282672a4bc5482524858f89c215fca19f5affc6e4d715ee8b262f1c7e12a21fcc27e3d4f9e624a3b381fb2aa7e0" },
                { "gn", "84cf498a8742438697f767f8976874d1dd9ecb025d617fb1d2309aaf09575e55efc50248b51b0eb84509e74a53a667ff64f2d6f47b2a5f2eadf6378c326f316b" },
                { "gu-IN", "06745bb0cefd5c1f0f79cfdfaf56758ef16fb4eab32543a4c15f9568de07342d29279c34fe3e60ecd6937182b474082658745e5f409c3a7c6921e0f1dac4d707" },
                { "he", "41a620ebe5c06a08eb40cb3e1075b799e955e8c8cc707fc89db44697246597f3c76c782c2c81e1663e23c2757e805d6bff1878fad290931c5f2ed5dd031fc1da" },
                { "hi-IN", "6d121ccdc0ed475727aef014bc80cf823c78fe0880122f022dfb91319b9095477d1601ee7b044144ab0aa64507d80253dabff10decbbac1b15c36f4c929d350a" },
                { "hr", "a2033e755bcf9cd09d7f9dfeace1204280d302c697477428dd88577b97e817f6895d869bb132eb727740ce471b4003ac27054d03efae94bff07ffce6f95ec006" },
                { "hsb", "5e0b00a76936e9a3312257aac47dcad237430c8b44697e2683f1db327fd22fa4511574df379df883e7d0224966ab97c9f22759504ba58e92872d2a8d2d5a08e5" },
                { "hu", "ebce4ee228f45fc9935794c6e2224f34f93e86633af2e42dd777d2263bc14f54eb5c92bc62a8ff89545dad2717de7c3c9d9702b5a2f65549e98d53a057f7ac14" },
                { "hy-AM", "bf6c36c56567a9fff1689717241f33e14567a5cbb6b99d60a8caa878a26255964e95f4fe622154ee64bc86fa697417da39c5ce84fe50c5aad0036f36000037bb" },
                { "ia", "5545fe6c10faa94b655bada910d66aec8acb701d4c4f021749bff5b90ff1f9c9c5e962e6341f1fdcaad60f75845c031c6d1701c9c2124b5139d7642c7da193e1" },
                { "id", "ac581ae8987662b34a3cd5d4c0c69e3b7ce4cc49c283469971c7d98a164ae951bec4876cdeccbe2a91c1a4f68148003dee27174bfe59481fb69454ad4d7cbd64" },
                { "is", "be64b5eab937604cb009e68b55649342a4a5fa60f3e08d472c499c86fefc9b505e405c0034fd7cab57f954c966018ac4e8c2bcb5b1d3bbbd3d4ed57764caf260" },
                { "it", "165f78ac6a88f77e255c1fcb6147221078495bfa7e30d9abb527c7a95a5706d2da04496de7a472488077c9fa33608b5fc9d45345aba802b0cab81e37758d999e" },
                { "ja", "aaa68c5c856238e93f2a0c473aefd93eaff10bbb0a9343197b247f1874a4d402be94e7735302be5cec1f0a60ca4c124f129e3b0499ddcf52986fd71bda9a93c7" },
                { "ka", "8a3c176a7cf03627193581cd780aafd4d021fb9a08e3a4026e959d1c8c37175a67f8cab09eee0c87f897f0f32b005bcda8b62614f3dc9e73f60ceead80bfda9c" },
                { "kab", "ac60253db023fe7f1ba7ed57eea48ec3045a50616289c25d9b4ca391e47e172b39158238861a3ca4f9fcf99116908f1398e9ef35bcf9739023bdd283ca4de0f3" },
                { "kk", "5bf497071b7033b46ba2f80263ac4c801c4f99ac54f9d3c98f4d683e61ca58959fb3c74a88e7f5ff81bb29b9366c9bdb643c57f6620f7840e24b2dd169df47a7" },
                { "km", "750939e6a2a6399776f0d5905b48f4ebca229c0d932b67f791102e4709ba8072c0a82131faf547fc03344a1b11aa709f196229cfc490a7ad85686aa5890512ab" },
                { "kn", "d23247feba0b62fbdfcce0963e3267f06abe85930afae7763f5c563c3ab67d0cca9e5159d410e878a89f5b90380076d6a9bb968245f5fde15365769ecda8f804" },
                { "ko", "035733118a92b8204ed32fdfef1a69bb2af00281b530e4dd028d2e1e0e1dd4a164a3c11565f711568d110c4e471f4a10e3290405645b5ade43c400cb50393bfe" },
                { "lij", "542e0c07b2fa88e78eb1f2f1584c99d2eca37af73813e481d24db0a608bbedf0771a0dcec261d1f3d6993f1fc60821b33f26e24fcbb865b1551234a71c4d35bd" },
                { "lt", "fd3f95e82defdf293f49c8bfdfe1ca5431806948eaeb1590588dbac3d284cc4b7e0ffcb3011fc3d6b89f16f289aa802267cb8574e1b41727a7240fea1035f2d9" },
                { "lv", "633655edd36a2698f330620529bc44200b5b44b1d9596e494ba8c5ca9935fdab44430283082dbfeb588cea2ae32e6f9e5e347ce5c30e8e6cd76421e2e815f046" },
                { "mk", "cfbfd4795bd77bfe8a5f299167b98ce99302400eca6bfcb48ec8c44903313191fc070d643509eea7d4d8ad21ddd2e8d1d504ce015c820f859905e43c7285589f" },
                { "mr", "e530ffea72cb55ec5c0d349fba56a05c1e48659251774947cda87e4012e143631be2547c5160125f5104e6ff763c8402bedaed04f36c4d6c15d456cf094eb963" },
                { "ms", "a0da4d42697f5d5a9b13a5d481a48b6a93d96d799fc6aac0d51e81a156d59c75689e927f9f926ef2a72b5031d19ab429a31c5280dcb4ef01067afa1bec8dc696" },
                { "my", "0d05b61b1962aabbefc992d2e462eac5ddadff27a3583ee368acb5209267b8ede16fbccbc60adc313ca52dd1b0ec15d356f8160e3725b23c96a5ac4c687bd062" },
                { "nb-NO", "f9464b96ccc738a13cd1afe5e2cdf06286d0ed19c935cda9ca1071e37ed241744a1c0a40e2b72b86cc178fdab600675c5b2c345de6461304eb206f7d8c57a00b" },
                { "ne-NP", "470e70b3bb2b48781add551536900547c721eb95f33494cdf75af6e94e4b17d275385f4eabb05cd80a64433e718d59623c3d7c0ff90b562161920f0db450b7f2" },
                { "nl", "d5b7890df0479e51330720fdbb52d4b73364ff876960d6f8e41dfa2b221079f75266eb0a9a2dec5092eb71802e6cbb0845b6443105c6946759a02ddb09c1f205" },
                { "nn-NO", "5f068ee36415bde89bd87fd89218b5620b4bafb619c08b05d595da83ea63f44a6d45de86bdc07f66f5adb9f90ad95e4e420ac83836fd096149c94253646d4efd" },
                { "oc", "bf52bf1123b8b05eed33a40c80e11fb5309fb8eefb7a1008ade3accf9ee5aed53405f84c4f8f803f5c6442f0d568baf75abc81b85c9fe9b2bdceded8f29ca77d" },
                { "pa-IN", "f9239b0cce580418b3c58ac2b416d0c2d0b450e5df262d402b2d2061ab9f5434433f64aa461268c38d24bf82b169b290f834340bae5bc8d2fc40b511a967a3f8" },
                { "pl", "009b5ad2e0cf2c841f0f8daa4b90a97bea6ea0d554b7febb24b18d2c85c7eb5c37814c3f9f92af3a53c8e55cfd1048d71461f75d3761778f95fa3ade00f898fd" },
                { "pt-BR", "382c1d10116ae8bf96083e718d151e6297c24d427c4fc89c2afbe6f130d7c16fcf6583e9dd7267451f19100cfa3b54b257f181a1a707b15124f9d7761c8972ab" },
                { "pt-PT", "3d4a9354bcd647b3d786557b3dd523b434a107d08dea96fb345b985f9479dd1499567efd87753842aa540386d1d6a41e2668100125bf64a94178cf2cb422d772" },
                { "rm", "cfa87f5d55d18630b1f93e33fa5d1a783d6583b009b949f44eede44386ad8a96fedf86766b7432c51541bb1ad5d16fb46ed2bb903fa09b3b05726b5f384a3a52" },
                { "ro", "af83b710d9df33c8e7e91f0f478227bdd1c2a9f903b9a151d16962e3286bbbd6524d7619e045cf0c6c94756d327898dbeee883cb6cb9c532e34a1e551e8e0750" },
                { "ru", "8c1200a6a20e7db72251a98db60ce9c96c0a4b31b1f396a9bba99e9aaff0eec7671b363e5da6f3623fab2c2a6e1858cf6e48884c4fa3db9e99332aa06c43d380" },
                { "sat", "000cda3eba4cab054092f557b156e8f1461e51dedbc09d1cd2d6b1fb8538a8b1bc6f7dc27861be8ac7c408dd8b17739f2744456638f6de2973109f669f9c7ebf" },
                { "sc", "c7081280c15ce7cbde72f1cce61c3c3ee5acf3cadb526795db21ab0ebe80ac1b138b34ecd45f85cd55e4314bfcafd4c2e6e11c0d040dbdb2afdf4e10acc2dcca" },
                { "sco", "011598e82efc97580a20b23f331b4888550599539323e30fee26d60e48f5f8fedaecd39d9842e7486c4def4c6b2817f16086c85f880ecebc00610868d697d9e8" },
                { "si", "21ecd5e4c304696248770dcbb33c5ca3c9ee76e3a2c14f6ea8a568cd777628bfd3d5afc28471bdfb6418b7848782dc9d3cadfc88c9262440cbb8f1d2f51495c9" },
                { "sk", "8107cf26a8f357ced23d60d685c0e647bb679bcf0c76db2b40f25095afbbb34693c8904f3455677e634514574e38829751656e5c9d3ee058d3abd498272a9667" },
                { "skr", "3d794a9cc54dff8e0f24fd159e59678f376a3e868752fe0d7f4421e1e13091175b79436fb3f2a2368320a8ec5f8c3f3692ee6767279adb4fe97a5d88de1fe246" },
                { "sl", "2d19f6a9e2e021eba7a910052e2e85babcb44889869922a39a0d20e66a9ee6fffb432b0fe2f40613ca9352cd7ea611de81f17c54ed42a5d9b311e168cc51b461" },
                { "son", "bf68f2a1b07504ead800898840375bc3e04e8a16ba02d53a597fc0eefa7a58bdef360182a51761413c547f8cfdb84632cb2d576d1c4d8ed5383396c8ee62c9cd" },
                { "sq", "61de603299571ebca1aec01b028d0e36347a5cf6df48c14dde63491f49f21b88046fa5939686dd297d7da9f65647911426328a004b8739ebc87e6af707d2dedb" },
                { "sr", "3fc2eb4cd93687656d702e3992594914cfac32169ad3cbba043f31049e7964643ab32e1e0db61b2654fb7422f17e298a324aeabf113c4b92f507ab731a97fee6" },
                { "sv-SE", "aa54e759df8bf91138d02352d8fff34a2741d2d91d50cc2880dca09c7ebda5e07c54bb54458e44fb55a48c88265f431b7807096e9adf32a9b2596e3d9dbf8081" },
                { "szl", "d005e4bbc5e85748b48a09c57f069752fae39967234df87384fe049778260c8eb801bb3d91f77b05171cf13a04bf825be88f1fef69b305a6d3558ec41c920f5c" },
                { "ta", "8de04a61b120362e61ffa6aba58be272bf7188fc4a06369898c13f6008526852a8b2eb7f97793dd1813d23a82d173f171ba191d60ab93442b0e5d5bb23c3ca17" },
                { "te", "a9c8c8a806d4c5a2d2cf70f753576241655e7194cc92aa70a430545d17af8fe8316b47d88a81546823b9aa000141e4377e2b483977b70b4353f0cbf14987ffeb" },
                { "tg", "27d180313a06fe0dbd093b0f0b0572c2c62125e92401bb666ca42afceb5d3bbb98f232cdc483c273578c1d042e798f3f0fa63fb3a6c897b447bbd28830cc9cb6" },
                { "th", "1b1942b83bd36940596ee7010d2aa6544b688ad957eaaca4448711664a37b634cf6b6d0e8a73cf2ec315a2eb54d5724188a73cb475081c9dd7e5c04e2bf9c981" },
                { "tl", "3551ea44851d1f886bfe2ed1eb958997a5b27aecfff6e461a654fb683ac97567edb579a9f808169cc2bb163082a84630bd1b4fdca9d05fd19ceb10fdf40077ca" },
                { "tr", "f33147820c3271f8fa7941f15baf5754d74b0b17fb03e67e8d5d07fb54a9773a47925b46e97d2a2ac08ab1e60b4b596f8ca5e33c9cfaa63831271765adb60eda" },
                { "trs", "3d97882891778aed9c2197f7d8f2b56a4cc8d12cba07274fc6b6922885fb29f65c96764c80c1e1b9326729ae82f81cf11397a8beec4f5bfa1d51a82d87c82a33" },
                { "uk", "a20e92ee1c6d8578c1c60e424598276b9916726583f04a8ab2d34e37a41f2d7acf270ee5ddee621a7df7fdebd3bdf5f8904d2bc4a60ab7b04637a9e75196e3b9" },
                { "ur", "825854615dc158f857140909641aa60537ffb69daa0f51bc4f21a2e848dce8093f94788b991f13353c6d547307676aa1689afaa141831cc949b48842d66acdd5" },
                { "uz", "8435f3c4516d4efa263bc5e4ecbbeb0fd9ae1aac1f63ca031bb21b24506ce5abf1b6f7ac6705e73bcdecd2b0a014461721aa93927aa9df03092b1413c96342f8" },
                { "vi", "78822f2e1c1f47d3ba668525b21d0eeaaabece748b09b35d7a7692e4b4c00bc76a2b365e7a95c1ce024e32b06bf7d2d68fd56f8d5d2e39b581d3556aebc5c50e" },
                { "xh", "b2d975f22a6c67094d21f63ff5c94de9dd7b1162d5c8baf9e65ef4f5b6a55061df2a5c310745975345cdc2e259c7e15ee4f376b07c7ab6ea6cba520b69e99cc2" },
                { "zh-CN", "00b65c60b16c8429a3790bfffd62f731af92e8f181cd70333022f101ce6849236c6aafce25126ecc3cca789717475e8b02280f355364f5aae974a1b8082b4e4b" },
                { "zh-TW", "1aca83e30b03fd53b93e9fa0babd3f73c9e325fb4f60064f07637e079778ca2387592a2f19766c4121705b1e225f5d85f8a59628fc5f41f4c0f4b8ee4d10bca3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "92a92d2f484cb02e86c33b2a4c3014e50cbbfe66028218fa37e8c9f8ffc0f48b0696d1bfdec29902f1093a65672715ac67efb101a88d96b13be89e13e44a4195" },
                { "af", "274a58925dc9f60366f9466729dbfe74a14408f092676785a6c1f37ff82ce7db3c7af75ddacd57618388fe04c0c1a08aab1054b4c6a24aadcc091bfed3968cfb" },
                { "an", "cb28f4ffa61e4337bb2936ff51d2c10393707bc7f403a3de706fda330fdbd9d946d5e06f0e8ebb39831e7160073c88eca7be2ae00978922842838dd7bfb318e4" },
                { "ar", "fd2fe000bbde62f1b81661b3db39951dbf579884ee92f182bf95d5a4140b96bfdcbd3d5d4f925f339fc9867f5907f2e4e2c5a30d4cda35ba48642c51dc2efb2f" },
                { "ast", "a0e015d7746050e47ae7e5656436a18f448e96a9c57de9b22f3e8d2aac8579c07ae3c22352de369faed4850132cf3a91b4537b53b5728552bd6bb7216d62afdc" },
                { "az", "6e44fb61aa0f49b69ad55fb0197874b32c811a792494637b8105c1b79f983b22e595bf3099745f0189cd5995506ed74181e7170f999389cc3cadd7e62fc477c6" },
                { "be", "248be8bb896cc670597b6e3ad764fe8a666f02dceb8dfbc6d743a5ecee14382843453ec74e1d84d88c742d17f50e40c27736d53fa5c10e44868f1288dd499012" },
                { "bg", "66d1a7b23811902b347c8a26d5e2ee11e7e0b6946b2c6c8dc5051b220f447a997aadf86647817b1366b7036a8c9e353fb8ad425eeb4e12e536d3d5c4616df473" },
                { "bn", "4474d9acb067a1fbaafee182ad1634f80a0bfdf8235073d01c6d4978348ee1d3bc6c0ed51fc63e08bd025f169d8591bcb62320f835af908c84d0c9bd04c0e4b5" },
                { "br", "d8bf4f8b20d822cdef9d3664951887a89218ad7c5b5dee3ae4f381319c9ca20af475a09317fd8a4d32669b552715ea8ddb16b14492d4963d83a933e128bfa9ac" },
                { "bs", "1fd1ac88b6a4e4177da1d32db962eaa5e90a935d62a5bdc837e0b503fea111ba806a3b7f03e89c12b085ce1eee3e69a045e1dcf392baaa348c297c04c13b4abc" },
                { "ca", "5911db36fbceb7861ab1234aaa910d8260951769016365791465b51e250d41a8fc346510a835ac85425f68b2a6171ed45911ef198bb3d3776ca5eac7866faa08" },
                { "cak", "d5a65144943ca61081df829bfb292e5cac45fde8eb35060a6ef17692a1173519b47377ad8be90a8d029c29bd26f290f3e9366aafd796b6533c4fb2cc866a2c17" },
                { "cs", "cda95e543a324a34ad1b86cedac9eb4260636ce6edc1c9cd0ff685dd52227b5fb8da0dc096ef6e31bf956dc9bc3df260758b7ff8221651ebbf57d286a9f2061a" },
                { "cy", "b22909fa091090844e9f2766d827664f314e1657827a40a6e2d44f2861dde6475877ff28b4f5132327612b0e625bf31ef751f9714ad4b7e5b0e2bd611a5b1ea2" },
                { "da", "d67af46414ced1f844f6dd65e8d1ed5a445e87f534179bee1d2c5fab48f44a09e033e2d8c92f669e071201248b0dac3640f6ff2757b50ac410a418e6bfaae1f9" },
                { "de", "41c5c8f84dbc0771cf205f7fd0e9897900d04860fdaf2ddc2a5ae791e0d0d0bc80594c7bd40a6789c3bd19075d582a8c5b9fb62b786838d7cb77be1d013ce553" },
                { "dsb", "2747180570786eb96dcb1a3fc8a01941cd0e0452feacd38e292542acf52a2c1f7d819748c80aa786f96a5ea62e44f2ce4a97cc662077adb8e1cf640e6d96a63d" },
                { "el", "b890474177955f09a0f38d2f08f267ba6fdd0c61a9212035f8e9e8c40bcac13bc80ba02ce7afd58b8a8b7a3f2c0dbbf91343e2c42e5ad18a6ceaa8ce3cda0377" },
                { "en-CA", "e053831c4fc1f528aebd2e770da19ad4496e04ee2979f8e061bd384e153cd4cb6f0567eac40dbdb2cd2de6c401b5e9dcb177a06c1d089f988479e64019131f87" },
                { "en-GB", "9a32c8c08608f37247a5e4f0682bf48cfd91d4bd81c90858fa1dac2b1bb3995e2b8e54fecbb185fcc014056d808e2d49d6e1490637343b31545128cc4c99f7e0" },
                { "en-US", "947f0855390fc99d92f5a15fd4c6da2484b805315a0a79f070bc6ac201a7784de3bd9613568e5f5040f3284188f087a15c102ceaab0596382b60d25411a2e84e" },
                { "eo", "31f5725c3f949de24b67174546af152f9fe904dfeff8ece2fdc1f5ea4aca1e5daf7eb36f516f7a6d3e5af74a23e1395ac1df85d34d4624953edc816c787c3f11" },
                { "es-AR", "41bb51fa18de50ed2de53250e0cb33fb0ffba1efa35573c97535e8bf8bfe84103f08d4cbb9437fd0e2828503f40dbd25b192c59142d39f8984607fb68d9c7eea" },
                { "es-CL", "07cf01a3aaa1ca37865d9d057fc2f15a9f2ccdd18c4d044ffecf9476b65c6b106b1c397b1546fd515a3e1f7149c69f88781571b58a8141e5034d5c164f2e3232" },
                { "es-ES", "d2d1dc1f642a5b611c72b474bee1cf26ae3af65e38281e0110e18e622a0239d30f85727bfd75d050332932a0eaf29b597b9e7971b38a869e1f6bf25762d18a27" },
                { "es-MX", "75b8130aec59ae9fceb5c0f81a429fe4abf97703141abaf58477c7124dd0e16f47916ab6e6e3ce563897f18e89dd193159e6f2bc7a74eec576879f135012267b" },
                { "et", "b56ebc7443a55bede0ecbcd2a7e819d6c7e856428e4911e18e8f2e65e784091bf6b2596ab898f02ccebd588521907363e5064c4302b54ea443303c5744155273" },
                { "eu", "98c6edcbc51e82b15ff889d90217e2875818174db411a24a3407198a5e6505630a3a4a825cabee720bca0f64c2959a69942a6281d145cb7e380930afdaa1ac14" },
                { "fa", "866e563ae0ddb852c70e9356888573e692f70c3a4170803c2203382b384910a60ce344fc76ff2bc4e05e8fa67ece08ae2c96fa5918053bc53f71fe62af41cf87" },
                { "ff", "33051b6b01f16316d19858cd965c20795a5fa7fb8473f95fde43bad415a264821dbe99677160f27d8cbbff50e6a8772904e4fe6c7c7fa785cee59fc531c5a1c3" },
                { "fi", "48d34db80354c391175357f077afdb7e8bbfd6d22d61de319f99b1bc845131ee50b0b85590385bf3ee2ce575b6c173fc94b3f0a1505a258a60e55c5b7e908353" },
                { "fr", "357ee007ba5f69b3aec14b0659beae8868b530acb3ae97eddf4d8a9d527a7c80e16ee6bdaab138de57dd14d183689746a45c990dcb5ac0463704a3bb6c799e1a" },
                { "fur", "84782a9c79aa6552585db2ae5eb86e3d859d8e005587b5a7996de69cd244767206e52f6b1886b00b8516e1184e20d214779ca7041082ba2e81cbf9a93e8227dd" },
                { "fy-NL", "c8fedb402daeec8c48f155917aa1567ab8577aa29baea513ac9fbba178114777e30331d2e0e85ef9aa7eb78573dcb1a6b2033f879270865cf993e63a199791e3" },
                { "ga-IE", "88a1a6f0174f6b90b78b499dacaed28d7deaa9abab2413a821f4f7f79cb82505669c5ade4dc1cfd8c69a169a7d78a1bdd82598f9528eeb4dccc5e0e24ddf913d" },
                { "gd", "891d37123c66cfc2c55ccc64b815037fcec86560ae6e9e5420a142e767f56bbae663f01b66a8f9b0e504a13aba7c2978168693a0460e0564b03d51f442b3d0b1" },
                { "gl", "94f0b2dd6adf4e38a7cd334005fa67529cd0d1ebc457072ccf5ab4cc29246a92a393d8723fe9844700ef4887990724ceec7f6b23651bd98e7451695b4f322ace" },
                { "gn", "b0664e4e950c01d4d78ac8e32756a7f9051d61055ffd08ae09efad19d8e376d4f59f644c4d16b625cf15d03ffb355e1eadac157e7c5ba7a2abd35b4dc4df3976" },
                { "gu-IN", "49899cfaf275f4c6127a224f9ab8774985ba59e506d9b5fc4939464cf1fa4c18f52ef4184d6d3ace96c6b6bbc72e57f9a23133c8e520058bbabe7ff053cf0734" },
                { "he", "6648abb629e082ac7dc17083e9b336f90140f5e3d817b5686eba00356b378aa8b59b39f6c343522c95f468ace94965f4ca3f765d28e3f162e9ff7af7750ff6fb" },
                { "hi-IN", "5e8a0dac622f43ce4f3420ce4215b08b179ebcbdb265b67597c75039babee07a65dadcdc87bb0279f9b5fa630b5e030ca854ed7ce29fb99c82eeb70dfff2f258" },
                { "hr", "1239d5b984a88c8c2cfb70d0e5438628a02c04ccba780c237fe2b4a9a9a7dda8f986a90c2fc49b8d84228c85d2678ddf08ab3a0ef37cbfc095d812486f10c359" },
                { "hsb", "46333ea7b146aa6dcd7c356204a4bb03d63752039ad896ca648fb762fbdf16871ac57ecbd11772a7d640589883fd4fadfd2b6bfa8e9fafd9507a4bdcad859cf1" },
                { "hu", "9d168c34f4eccf51a40f40d534c1f220e02855f5a29bc55d86c91c00eb873cd7d8bf05dc77d3482a797ad3b3890666224db84253694e2ff577221bb2a634ab8d" },
                { "hy-AM", "0d7bdd07684676938db1fd244b0afdafccbff351f57643ca38579561ed442843ad77492eca63832f4f3f0a1971b43cc439d08e79e2611752f3af939fbf2ba2cb" },
                { "ia", "df4fbb8df8e0e39ebb82dc31c483c43e6256a8ee076f5073cecb090c8d66d8b6dabf1d5ff421fdf55ecc5b4fc89eb888d172fe165243a56ad4ae8f815506dbe9" },
                { "id", "c0f5317f19f37742f1ea249d6d9fb5d652f75a2c5c4e260e931fdce202c3528034d8f5771966935c2b7004c22007e19e89fbe8255478df017367d0829e3e9121" },
                { "is", "cc3e4c8796c248188db0a6f92db803f2ce66a31202874b0c645a5fe1685a3d861e4759b19742c1f9ca560304a0f0cfc6b6e80c366aee1dc582f1913cc60b8998" },
                { "it", "54f6e150bff4f0f43644defba6e7ba4279832b212c84ac50f0a66fd1d7eb3b1d6ea11be5eaf982801c13c5d71e4f9acc98bad40af80a56da9e7ac036d194dfb7" },
                { "ja", "79b9753a8b7ad9af643cda02598338973718fcef45011c96fb142ee1484fd23537a962e71045b09a4348ac71aaf3fab8477fff02701ab945ce9b8da77704967d" },
                { "ka", "9a9bba0bc2f52a43c2df7a03be058541023feef9e7d2e621acc8bd1c6b51f8a02d26a75b141d60406d195cda5b1812845c6b42cfd4e610a89754f75adf3beef3" },
                { "kab", "b602a59ba31ab624c8fc55b2874ea695bd46f944835e93c5ed21c0ff2d886a34fbeb46485ddb2196129b3687dd2ec184a0a85376b0518d0abc6c0407cc6f4fd0" },
                { "kk", "2f2306e83c4f478da90603c795f2a89fd0e776f50b64ea39029e235b33b46679365d6937c3c8a89aeb100e69c0c1ec9f4bc1d8b18692f6ac5f12b46f64c9c41e" },
                { "km", "9b00ee4d142dcaa04a270c35c69504d6df11472855d4c54e3b36b9186d9bb3ec1e553f0d237c8fac7fb7ac48c40a20f4c3e274d897da7bb99c45621fc2eb9765" },
                { "kn", "c658a2de1784759ef38462dda44dba6f35bbdd1a5d09090c37603af99c8756f4430ad0c8560228a081c2f75a24adafcae3f88bc59ee9aff623f6a912d0091fd9" },
                { "ko", "fb5438ef5842eb1ef454e8fa452bafb948ee009ddac2eab374fbd0b634601ca2810145f6293a8998bdd53aa7e3c1ab08f3830aa28868b0e46c03413cce809bf0" },
                { "lij", "dbdad444dd5ac19f0e87e407d7c77c875d1c432932793315b81d593d47f71f7c995664b0a9c69d802762c17f972a6cd4888f3736811dc0e8928e94156cb19000" },
                { "lt", "f98a9836baec3667d5998bbe21c9685eaec5b7767109f087543269e631c222805da68e0612d865ade18c02c8fc741eaf72c3600bc57aefe23f720a34a3083b96" },
                { "lv", "b23f9d4faed65235de4b14fe35211489ad53a71dfd80104c3fcce181a1ac9fb5ad9555f06abd0504887d500d0e52d47aaf28136a3ed095457b6e32fc96772424" },
                { "mk", "1d9468ce9c8df446a585c70547d911f274275e5725d8e002ed282427e3e041095562368d0ba152759deda6a82d2faf928e68c6f88c1ecbc95885e9436b2869d3" },
                { "mr", "181f69fe268765a03d8cfbfee2c74c2875671506274f38076edbdf5f2f6faac0c0b53267b15e472808a130d0c39ee8f95b86b537c9638c2b2cf0f112c523b997" },
                { "ms", "db90cd6429607ed0d12ea4062fa918ec93d3a118fbb0f9abb9b7e8a6a0bab19fc1fa96a3e8844fd186d9ff272353868ef6bb20644f3e106dff52986e83fa6266" },
                { "my", "e7ec078a9ff2b4296004241e98c0153412752d808711747690746f09c84ac467aa2bdb6506aa042b328b0ff880ac99bc9c913b359f5ce152ee75baed9f925fd2" },
                { "nb-NO", "1a254790837d6ec7428baa79c4e1e02000bcbcd64528687d0e25b78298ceff474bcd908b93574eb7204b0da6b7c26abd74fa860319159149bd20cd0a9e758a46" },
                { "ne-NP", "7f9de2f2f18f3da4fe35afc4661ff4db5a4725985a7eff43bdac7e32de208d2025c7f3d0039dd34e188f94223551c6b5cd31b9f8f4de50c9d42e198c64310231" },
                { "nl", "6d3540e5243d0afa2154391c550139f9faa3512819c2eaeb3471d01b72ae944c3f7451b5b79dd45eaee3ddab9b2393c26dde73ab0fcf0256181354877c35e96d" },
                { "nn-NO", "0db0f74dc11db867d3a6acf1173c82a1d76b846721bd9c0730e97061bb1821d95233d080d97e94e2ec2c406f6cebd2001f13f85ba1d34c8892554818d60d0f92" },
                { "oc", "5689b12229938460a4f91542ed4fa5f61fcf0aef8396694a21d6e649d72cfdbf6949fff6d2e05ca2f5aab6b0079c23d571716e9a036c1200a628ef480a5cff38" },
                { "pa-IN", "9cbdd642b817bc2f1575bd4d93ae04816b2297499c98699037b1501d641660d1ca86e1d34dada13d1875b11ff1c312a0443a40dc0c140c2d86a9b6e93b6d760c" },
                { "pl", "b2df8f99ffc79e2d2e41fb2ee2c3757ab4d469070043e5dfb24c87ca17f805bb2fbf288ff856f83bf5266dfe1199fd6b173c835c45853db89cbbf98faebb3b33" },
                { "pt-BR", "8f58a10232a6974dc72addc5ad369ee0eb2afdae29a76b09b4552b155f625926ed2a85ec5baf516fe3dc4077a42983ee18760e051a3ec264f8eac8748ca53038" },
                { "pt-PT", "b792c3d365adfa33501b0c2b243547115a80cd75d144dfd3f9b7833ccd9accbd1929b26332dbefc7459839985db7ee698876ef45e1551121e1fa54477ff7c952" },
                { "rm", "4339b955d10286ef54eeb7117416108f96e27c168c660538044b4ef6efff22f022d1e3e46ba70d1070dee8eb0bf6e093f9e4ec8bd9b44286076a21bebd3e7a83" },
                { "ro", "5237127dbbb9449e56506f97d2de7ec5d2c1b0bd5c483c8a819af66b1dfa77fe16674d3f457e4c7ba260819a59d9fda2523cd3368cd6df64b676bbdd2db4c8ac" },
                { "ru", "82e5320bb03959d5c5a525405fd3f39407439566c32d18a22fcd38290181b45aa3b3c38542acb0b2ab2c3045f5dc8a823feb2949b5941d8e54f868d37af9cfdd" },
                { "sat", "ec63d73e47cc10a893674d5144146bdfe8a7e3d003be46e3fed01ce730f1dd16a35ab657f4edba95252aaaf1d9112cda63de23e8df981f4c690029b5c771a85b" },
                { "sc", "05dbe4312005ec672426a1f4e2ce0febeb4a70f0d237ce06dd105b5b87b8c0a19deb26869daf746233df8dcf29b959de81f2345a64757d4f368e78c868c5d492" },
                { "sco", "82d406c73bda535e2e940e7f6c19a19e63ba5ac8258129187b51f5388263218ed4e0fe7ea95c2de72e6cf7c9ad47df949b0ea8f75487fe48aba07429a36d64c2" },
                { "si", "6bc92d65b1e894fa340e855d72fd279191e0492c735564cecd9e898170142ef671913ccb3c840d77bb5851551c1b1cead4f45c710c05ad1a3ce7011301025065" },
                { "sk", "f88b221c89876c494428b8073a3874fd668f4743960cc1da92cd1abe73bae0b04d6766b252a81b1c148ff2edc3fd8acb079aea4affa6ad0f559d257847dec436" },
                { "skr", "151d351a145b33a127a3a1c97a8ec823aae5601b0ba2b286175f2433a6b0fa7cb94bc9778ec13d6ca5d305c60abc67ef6ef74970559229036da96708091b357c" },
                { "sl", "6e1407d48c1f5f47ae553e30b1174ceb6253f017777cfbbfc3df364181cfb168be11ba3b8be494fa203cf66531809e13b5442e5f9c275e4b0b045e6cac2acb70" },
                { "son", "32d2acb7260e0474da6bedc9fd0406a5ead722f22be6dea7937a797455572a3c984ca45f50d3c1e95af70b0fa1eeee56f52ae9ca168518a24e67439255760c50" },
                { "sq", "992a1d8b62d10e7915074ddeb03f110ba6298ba3a01d62c4f5017f2c0dc7e3297086eea3a34e9f9501922950bb4b592c9b1888c01df4d66fdd43cc0e233e8062" },
                { "sr", "8d37101e72f023673dce4d9525f31d6d253fa2ca742d4cc503f14fec60189e781407f0571153472db56a230e4c993eef3b5c4cd7a4a999d1ef5de4499b9eb947" },
                { "sv-SE", "b123410582d75eb56bdbdc2375c6a74862418411a34f04b56e4a73cadceff604d21ec782d91b9217dff3f6658d615dd77fb77d6a30d9036d6e2957f7f9cf52ec" },
                { "szl", "7ffc973798105f6403e3af0b02b5ec5f77710603413fc369775e5a8e859fa561c9fff9f4307836da9542d63373720f197fe0f7a8d1b52fb85bf762596fe62ed7" },
                { "ta", "4c819a498b00d753e7c7e04ad6705cdde6c1a3d3aab70f5a9aa4a2c097c977c8699c2a6318aa5e6ba4ea6d7916754749be510b6d9ffd4762b7da612474a50564" },
                { "te", "5f10e58fd2796cee6b61230417e0b68c55f1f6ebe2f37cc0cc03e35835caa9a511da11926358cbebc60b8eba5f869cceabd47c7b7962c02ef743bc2892f68b80" },
                { "tg", "5a1c4825d1d07f22c441413898aebf282378212b41057036c1a7c6aacf3afda6cd2c01a8feb2c734dbc6749e53780459513a3af24feee77cf184b1ff704b7a6c" },
                { "th", "225fa61c49f21d3043f476c9ac5ede35bedad58906bc9b4f6c83ba308030754951db91aa2798cdf86b546cbae64ea0d39f65fe00d376c88fb9fa0e9e45b2b55a" },
                { "tl", "288ae8282fad0cf86557dc3e5f0760ab2b8a2de8381ab882bf539690bd7c3f185be3146710a2b3ac6717e9c70d646fc4ad0e3ce3ce7368e28c043bb1ef4abc5d" },
                { "tr", "fedc31b550a5bb70656daf19e2bedcc2a15820a43787241bd2e28c743b246fea2248d153d08f2d081e81f472fb824ca88025a9df1c7e3ff5419855af52c89bf6" },
                { "trs", "b0601a7e4b3719ba53583506d264b43ff2b7c1244bb9cdae51a4f551c8e066e96fdc0d703ce5cb681c1e44e2cb917fe727249d7b22c0516a44e7b03970bb8f96" },
                { "uk", "c4a7912c79361a72ff84c1cb0bbc283a19dfd29b04b69f52ebe91fdb86a963694bc9061bd1ca604de5008a4ca9a308cc6a05579d4cc47f5c5af88817ec291b74" },
                { "ur", "3fcad6aad9dc856b48f8893cb7ad4cc04508ddafd6ead5a1bc1ab22ef8fb3e4258a70f14c6494681fc1152b72654e8a600e3d88d1f30504e5c3173f047183203" },
                { "uz", "2aea565125e421f32223789b1ec03263e0165f6680492167bcec0db6e10e58425e46fda115a8b0b39fc1437cd1a0115e8ff8d6e6a170fb8571bbb2a4c0af1741" },
                { "vi", "f4219ebed12f4a51c378a4c3558d9dc549158b78cff97ee9093331a2d4d6daa000c4ba64a974fc5a7a8f06b2f3dd2347154c486878b02443332a59064ea7dcc9" },
                { "xh", "8dfb7914e1c97d359f8971b3fa010de57f3ac96013670a6475569c5746745b5350b45900f0d14db9513a7e37434a2ba3a8ad71156b3a0ca40bca798cc4a2224c" },
                { "zh-CN", "b9d293ffcbecf261330686e8ca266aaac0947ab977d99354d574b335065d41f8d56f090a7f04402acdcdd5bd760d11e4250b94645d1cf389eb01de6bf6b16307" },
                { "zh-TW", "e3696ddd3233a98e48304571b1f50dbdcbae8bc388146b440687e12042bd8295d6fc976638717237db840014b3c1a0547824f3601bfa18714261a3ae08944e8e" }
            };
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
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
                return versions[^1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
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
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return [.. sums];
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return [];
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
