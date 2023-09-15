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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "118.0b9";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/118.0b9/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "7e8c180eb9065f778e57b440a97742cba9c08c76ad040b67076662e9bcb702c09577e186305e5cf642bcf42282655506b97bc439b9e9c756b3ef7600c2fff1d3" },
                { "af", "ecb55c6a2c783410fb63702ba0af0e2261104e5691c6d8aa7e4dabaccef18db7d0a285baaff00bcc4e6cbfe1b800fd424f2b80a0636776c53381514b33a93611" },
                { "an", "8eaf57d3ce30db335eaf247f048c462b00d66da3a04ff0d2ec159f2730c0b9048949ff0c02c3da3718e8b6b7274a7274d63faad15b966323e12760e6f3187d53" },
                { "ar", "24c8114cc5fe91e0667fa268441d07ba26f6de8be797ef30326b08c98d6f5a34801607c9271fbbebb089d69df7f80ab83488e3307609b8b55df665ffb9451721" },
                { "ast", "79f953e23496e1f17b5ce10b183a71264a440d99bbaad760bce1c03cec1715570f7c3edadc3390b625131420c22cfc9750108207c63513eebd59783a164edb79" },
                { "az", "133a2b0fdfdf02b877447d98e078e6480a24e566af585bfbd4ef85161bcec49905d0a7920e04d1d546ba76ad673a7763cd56f0180dc9d583d347f61767496a6c" },
                { "be", "f3a0bfe4a0bb71acae39bcdabfe6aff53f423c94909339f92e932bca2b7c0a594e5f55de84a8e422473c83bb5e6e2f987fb51782ebeeba2a40bd0300c9a0ba03" },
                { "bg", "c6463ccf37668ac9ea3eb79bf4ce47e10bdb7be3557c777c792a5b66cbd9697aeb88b54b4822b4f8bab10d8b275b4d03d12bdd9bfd9513514e9a6ee0bee92b66" },
                { "bn", "774c302f844f07f2e138fd23e0c00b14d62a8c345572cc5a867c2b15169e6ed6599f566d2cc7f4db53c7287f3843240fddf54df91b648a198d8c5c410710bae0" },
                { "br", "c280c9c81354e03324c068b983b2811f5c0cd2b0a96808e7f1fb75004158c05a44f883da0a7318f58dd04597f09cde791ed0dc0befd32a566379dd38bee9cd78" },
                { "bs", "e11417c90b7210e26f5036504d20bd62a38e2a7f7ab8b592e9cb31f469f4c3a7e3a0e7539b70480817384ff36e91260413aa3d4721ccc1f56a6da5a10b4785e2" },
                { "ca", "177a0c07a59c693b9bada20641fab2284874029c9ad1f138fd81bc3d58c14f0344e67b08447475a5d6a2592e30f0315469878894c8e861475923f4f99cf844f7" },
                { "cak", "d228e9043f95a26b1bc521ac664b116c6e47f4a1bf57cc9753de5f401803fcad91824d8ccd82c6945736cf5e6f78ba916dc2fc33aeb5ce57226571d4f7585a90" },
                { "cs", "e6d61da8df41f1da8c16e7fe88d1bc087a015ae58ac0999fb5b776edcb960d1165965d97d8c4ea900d0a8d8307e7e680d6a648db1c939fcc84cdc1c4e0b2091d" },
                { "cy", "e6142591da3da88bf9b380f68235a6b4e9f694df88dfdd66507eaab73e273fab76ab3e3f2733046ee0d07bd560578797d0325d896ef976615c71bb81346790ef" },
                { "da", "c424f1e3ff7c48cfe84ab419919318e2b58801e51805befdbc982177dd9d4ef54dd95e181bc3aab7f7a7794a8c970a5a565a9d8fa57504332f50c91b0af54f3b" },
                { "de", "4960b41eef4c23869f33645a1322062eafbcb9e82ea4b5929bf2484289dd42ce4ccb63813d253c50beb7b0779ab5666f15b643f181790338afb64a4f485ebeba" },
                { "dsb", "ba581e5ce3388e91f81ba885bfd8ec2b24d361950914e6d9164d6ab54980899e8f0edfa833cb7378fa9b830090e9bcd0ebb91453b3f959e32d372440a69f4315" },
                { "el", "59a5641eee3d07e1ff617979dbb125f643a502967427f9b66d677b77477a982bfaf187c9e00b7bd7f79c983055c04d29fb0a37257af5d94947d0e5d47fa648f2" },
                { "en-CA", "e6913e21f9da532e3b98a0508aa20557432ea39313c9a34ea21148dfb2c38b622de1a08427946cf460b95fb1048990ce60a1795f62b9a3779f1243e21053caf7" },
                { "en-GB", "c83e4578098af9600a7de66c85c8362ca4111c98d2a21167f65a873c48649b408e9f55a74e36088bb2c12117493aa3ee3506bffb8c8f2cf5bc3ae4172e9bfa8a" },
                { "en-US", "aeae0119719c1af1d88df16e9a29cec33b5bd674368bf8864f40ec56ee4398f7074c1c8d9b7c45dc7495a1d901ee908ad9059cee7e732dacb85c031a98ddbb71" },
                { "eo", "e3a38653e62391768348d7d80275a85dd7b5776a88fa18e744dd8a4a4e3996985e9857332385d7cb91fa316dedb45d38556b003f7eb74390b1bb6ce941106c79" },
                { "es-AR", "ac756689a5fe27439d79e37030e509940f214671915455fb0d8418867013f936a73a53bb898e89a8e8b74d866123def003709ea53980f719cf1d68d719b4b915" },
                { "es-CL", "7526e9305951263ffd927427ec3a3566bf15e8d2857d4c07f11bb499f4adac9faaae28f29f15cb436e5b75afae7c53b1480d2a970b795ab773370db824123bf6" },
                { "es-ES", "ad4eefd81d5f11795b7f278675ef05c7f2b3faedac71ab4a44bf5157d2f515a74fd4bc18d7c6ef1d085874a921941a725ef54f4d75870b29e76776ccaca90c2e" },
                { "es-MX", "348a217a6fe8f1a1e9b5693c2a19666e4b00eaae4486f5e918f05a1b6f3651af69e3cc084adfd82935b307b428d592be48a718e29221db3604bcb5ef08ba1036" },
                { "et", "7778f8b340dd9d4d255aad1a8a7f3a360848f84b5392b1cba735b6d4b0849d91ac03dbd97b6e26ef3ce03f9b58dc992c468c5672fd7abbcd94c7ab2f0b20a397" },
                { "eu", "d46b7532274df3e3c6bcac1976289397d39fee9b6f5f631450eeb1ebfbc33f90fb53c73930171277a5cc3972e6e351df3a0fa0e4e51512448b98ea89798269bf" },
                { "fa", "bcb63468da4cd166e4422c38a27419cb2da657afcae03e2c6caefa0e2aca00544ef3ca4db34ac089de0c1103a9567fa1dc301579daa656699585ad246a9fa7eb" },
                { "ff", "9a7ff29af2a1f5cc17c684ea0f55677ba57d84953b1656f5a0ed024c49b4bb04be5c30846554c855aa23a75c26932392989f0c1457955db6e5ed8b9faa4fabd0" },
                { "fi", "0893c47912c8f8900424467322b1aeec0111baa406453e8a33c2454fd6a2ce237e8dc749dd8c87d9985fdf2acefabc7fda2f3860ee808f10711b353ebab28404" },
                { "fr", "c3c681f09e80cfb230be8db4386af5b1e09c9e612a612ebb236b7872ddab47db66869b76be0ebe90ecfc0c5eabfdacbbad0de7a7d5073a5494614fefd25e82ee" },
                { "fur", "7529913cc71c6d555fb7168664d08ad695bf0da1a02cb7f8a130ba81ca2692cedcfaed4c3fc5b7930a2cb139065da44fdf8cf27b3e2190958cbf103a767240e8" },
                { "fy-NL", "285e14278befe6057ff5ae36f35eb36162456f4b8896f2a198b2c41ba643c3369cab9e292d79a0fe65ad6c4c547d55d2f3c48e4e9075ae65724584ac6c9837db" },
                { "ga-IE", "21031131764201abc470ed7d3d50011b84ceb961157f8dcfb1acb5bc87ac794234f353d25e5dce48fe84d6dcaa72b4626b3de92dbc197e2b8c4fb94092cc9808" },
                { "gd", "1a2aa8bf54077e34c89981411b201713cad650703f51f039273fe9ccc19b40ba9d7f2acdc3d5549c373108a3e006037f5861351e667c8fe37a0ca69ceaa4019b" },
                { "gl", "9006996e5fb723d54a4da7f02bddec72648b96334bb9f176c14f413279f9d71bdb2b2d02224dad87d69a5f65357ece09168cd13631b5fbd60ab6e6d1dac6004e" },
                { "gn", "120aca7d5e0439f45b668980a91bcbb5783e50f9f64f393d73030b79aec3f027f5eb0db6b067fbf0536dc3b18256cd57bb295cae0a891cc38fdc73288c3ed5fb" },
                { "gu-IN", "db4d7d79146d05e428ae3b04fdf6e36784d780d48126db8e6bbd4e78089aa55156011e51ddae66ea8d871fa29e0de5e98a8b455ecbcdb0be4baa0243b20066c5" },
                { "he", "bae87a8cfe4dd0683840e648e8d74390d26bcd0126c8ef020829ef7129439667a1e95efa1261839900968c7ff50f8d5029288d64a535977d816de4a4befeb186" },
                { "hi-IN", "e49a3281c16b560a94faeafbb001a678bcbca13860dcf0b592c0d0878b484b0630f77cacda20b271228ad57c4e54d780cfff0ed356245d6d74d0ac8cedc3e6e3" },
                { "hr", "098f1da202a9e7e2c8a2deef71e6c5c6666004ebb965d2b857da151d6fe4ff3b7944230299369e3132e4b94978edb1915c2792122dc6e6306b5e36868e58d384" },
                { "hsb", "53d80e8aa866c5df0e97293476d81538f92ecf4afcfa7e71aa2302c3cfa0d4f737cb86fd828fd8075a1da4eee4018e6a1b300db680dce4cb3ce326d0659d96f8" },
                { "hu", "4c3eac8c7ef3309f71b6907636b839caaf3628369e279e6d1f50eea95895ae19296eb7c8a9c098963cbbecfe7ddbb52005955c5191e2f06a4e8f049c0e5c23a8" },
                { "hy-AM", "c6c7445afce9b267d7776fe8df1e690ff05dba0995890d8279c9ce62edb5bdd8b19522206a60e2ffc076b07dd1e35c3d82663817d6aa748f3b5eb8044cb999f8" },
                { "ia", "8f8c3fed1e58b483f622f4ac0b17ad54435275414724c7389ba6fb1db4e3aced7c640e3b6853d3c557597a6f270565a72c66b51d8e39371684692b18e42e6942" },
                { "id", "71c9bf9cb030ba62edffdf1457101ebca30fbe01d0cca471b9c30b3674a19dcc0001d4406b1845da3efdd61c43b670d99413d09367357825173800db8bb34817" },
                { "is", "8088bfcfe64e4f10b88df3110ce4068961fbe0902088ececa507543b422b20b60434587766963645a86d7b1a8e635ffcade145a9c56fecee7d8beac4a88c03ae" },
                { "it", "ca2128a2e7c14c4b0e49d18c09c7b201d43d57f3bb4b13666f72977c287207c92a2869e0f8758cbb9f3836289e1041770b53573072a6e48ba98f154e3a5a872a" },
                { "ja", "9064a0ce3640a07a198b014679b911fe735bf95012eabc663b320a05b416475b0275ad82f5e6d3773bb288e6c950cd0ce41516126d3ceddbcdfba88087d1e9b1" },
                { "ka", "853172736d4986e9ad34da77e9f6b8e2bf4d9fedd239d39be5a8310fdbc75a6fe6b2c12cced97de9e877f7d8fded02ad9c16c72099f1a117a25b45283cb4444e" },
                { "kab", "808116ce38d5eb80fff606fd209cfa89e9ac2f87170c09eeec1b36d02ba06a2a30a24e04158fabdb7438fbe2588b35c71e023f47a0b82c633f95daddb03af1a1" },
                { "kk", "1a6256083a5ff370764a7034047238288afca6d879769e7bfec4208eac67eff686a1ab23745a272a3936c1c7ba7ed9369ee5c66f3be0baa5614895c380c962fc" },
                { "km", "7d70d1ae2c486aa40656267b85ad6221f7dfcc4601414d31bca487a0cddb374f692c9426bf22f6bcdd16b29073b2837c364f40ac74d14459041e43c8b9d5bbc4" },
                { "kn", "afba60bd77e11385387b3c7cb5903b04c3bee840970d8c616a79d5fd43abf121f4014c04830b9ed7f5a342fcd8f7c58b2e1ddb35f220fbc28bd0f3f9190745be" },
                { "ko", "2bb64ca476b65442a3df9d0aaf891e7e1ee520e682c702b5f8c936d746c36dd617d9e54b4208e76d0d28f70f31a4158f116bc957d50559b7e915adb2f0e593aa" },
                { "lij", "cba02c2419f2036deadb630949ee70ee2fb684a542a738e73b73d13ebf52d60e15ede7490f8c3fdb77959817ebd902654eee971ea0f2f0ff9f886a0e6aaf191e" },
                { "lt", "e8f5e48fc5d13c9e8bd5e935f722c3cf9d38e95ada8acd4b2fc4ce87b7d9fed7122b71c313869014691b9cbf799e94f476c1250d3720da4f67faa955ecff8262" },
                { "lv", "860eaedbd9a5024b21fc70e59793029616e637ed0b7eb5ad8cd0ba23cf1e77bb196dbf046d127d5229428b6b7544ce946c0aa4d4f031c68022d3c2942f31955b" },
                { "mk", "f3891aa0b374075f6efd5946cdcd7cb91917cb7be0ab254d433c2a0933e186c3b8ec64584ed5c755f7846478d6774be545ee728cd2cb3462419aa599e1803204" },
                { "mr", "15b9de966156a881200cd49ccfe52848186d54caf26cf6e62033012f32d6c7ac955165308de9d94f03b179705c26db272378b533661bf9897ffbfcb603b56c74" },
                { "ms", "c6a2eee4c98f24262d0800a58eea00cc4d31bb73c13b04dd6a117f7bc887fe8387799a6b48e65003f197fe0ceda841e2ad9182bf7ed47dadec30c976cf312ec5" },
                { "my", "e38249a560b35fc93bb2b38cec1f962130caee790cd05be700658720f37d18e25916d269b791a13ff14c71ef8c8101821867b0faaf80d708ea0610a81ed77f26" },
                { "nb-NO", "731c471212f04a6ddb0edd6f5ebe80dcc88cdcdf2b95a816f5b6c11e609c3ebf04e589f4918d5eec426841be932599477154a95b6e784f275b9377a763d1bee8" },
                { "ne-NP", "f0dbe740ccf8653abd019fd712f1d188acb81ffb26416704b60b2e0d2f35e86b7b34e144a4f69b7bbb5cd859051cb3ecbf3f85e3a07ca8bd306d0be959f05263" },
                { "nl", "ddbaa794a221e166a249695ae95c16b7a406713a706ec2d45865327fdb35dee50c63aa053a176ec62dc04187e26fb8c2555d10671c0878868c5ce2964f0e0965" },
                { "nn-NO", "7948c73e3aa4bacb6d30eb53d61f1da6ebcb13d78341e071f5c465d6242f125f4cb223994ae5dc4061c93ccf43d481ba8b57d68efb472e1ada41cf704555397c" },
                { "oc", "5d3fb98426fc876efd9450dfe06f7d67c9061bfa5e51a155ba6bce3392bd1ed516a7017a1bb91213abe421e3579e763547c3cf46196215d695abdfb80aa8679d" },
                { "pa-IN", "8de0edb60a482d7b746adec1cdcc1aeaf6f888d074ab82a0a048ed33080427f9eae2874ea21f1b6a35b0cfdbedf4252f935287c7578ad6fd1d8eab695e46762e" },
                { "pl", "51d9921ce056761bce491345bca35abf132cf4fcbc336c6f8c3df58fc82df1651b582d0991083591e37dd5547c50d391e4c4463b6f61601ef0f970ef64b7b97f" },
                { "pt-BR", "0acc47aa16bd4a89cd0a5f4f2005a09a883df4f11ee1275c305bdd5b94945bdee27c160427ad3fcd90f73d497fd5e2aa7fcb36e5d972f6002ae4819d9e500cf7" },
                { "pt-PT", "b3c2e720ef3a73104b51bdc39972ce7581d0348122680449e8097f3ea89c449531af4fbd842c242beeb19664308e5cdd853a08009030e87b44a75ab6c0ffcee1" },
                { "rm", "a201769b705d45306cfb0bdbc5476f1411a56ee597ebe987ca3b1d0c8f7733c0cc831a0b2bfa482ee94fbacb2b5b0c0ca065ecfe0d1993f721810bd4eca69b71" },
                { "ro", "58b2b3e32554b44e8eee011e40076598731962ec507bffd93c3ed182fb7a83b98ca2f153c2cdb90c777ad1742187d9ab814644c333126d5e6b2168580fd88219" },
                { "ru", "e559dcf1d4b669943d98f0e123717c8f7a603954b22458085cea9c6f4d4e3880027853eedfd33fc15dfb972eaef2f122d67928419cbbe9694ae46920801df9af" },
                { "sc", "8a07315176b9e4463b7192082fd0108b4b9ddca04c5a6a95cc54061559bf148c8240fce262585c30eba1d709bd9df0a3c39e3ffdef1fd50f32637b8c34422851" },
                { "sco", "9b7962bb618666eae546da7787b77f7918866ca5ece7e4fc57a6ced1ac0d0010fc4142042293e68710cd71d5a21cfbeb752f820fc4d1af7af7d549f2693ff9ad" },
                { "si", "b3bd2b131afbd77651bec68c87a3f4bd4f6e1a5414057e2578e3fe43ec522d2c07e9140149bcfcd5a3509f668582ac7e980da8af3bae00ea46525b9b57a3db19" },
                { "sk", "6f2aa3114f6101344e59cf68c3619afc128319de49bd249b52f7146f9d455ebb96b9d62a79fb3ab3f772b339db9a9443d7638c1911dbf4b526d6dfdc453ccf73" },
                { "sl", "c2bc569219704c1eb3e99e972de44ab5d1a4b219fd61334fb8483786cfc6a68062793ec03aac3bc359033454f8fcd796202b707f434b29231065dcbc6dfce5b5" },
                { "son", "9dceabfbf2e3810b94c61ac114cc60ead74abbe953d153cd53c7ceabe854c5b7b43898ffa0a80f2057ad595fe5ec1702315b70407581cde8520fee29201f9996" },
                { "sq", "4898d6eff37665a61f6986dc3ed42f81a183c177f7394ff4e78f64fcc6111567cb3c3a4dee5a94ced6ce972ab2eda6a37c5ceac6ca72bb630eb1c4835df86957" },
                { "sr", "12db4463156bc51dd8d2b2817d0b159423cbf0b3c3c781ec4475d422c14db7e9c31388a754842d8f473350b2945d7316e6455b790e49051374a33fd6d5aa8f81" },
                { "sv-SE", "33e825c593b8fbf9ee00e16aafc728ea3859da5f8ae7676471d1c06629a582910705212ecedb3c23aff509b37aeaa989072369e4a6fd542ddecbc1a6628d7546" },
                { "szl", "fe33c5d9b913b4a50050e53d70f3ebc4f35e8eb0877c73d3088b808267eb09d9d0a0efba22fb832fa391d39a5e56a72fb10e5746b70821d9c8f45a634d907673" },
                { "ta", "b3cb8da641451059c4d05a912f0c10f33e6453e7a3294eb6b3dc5f649ead1dd3dd781d9da42bafa7f40f8174c65060747bb6e29178f8a62fcedb08e9d664a6ec" },
                { "te", "f38f5118583bde9a7fb2cd88962ed0628c420c74f5d3720bfc3af74d0197e3cc96b4dc8de801348c15f274fa744674a58808c82872a8f67044e79a7f9a7c42c4" },
                { "tg", "3432f8c6ac30cffc601ff6a790d83525eb4bb204762ce3b1faa9dc0023cb6e1fb3a2cb47863ce17ddfba64d4528348a53bfd8bd154e12a61733b902e6f3affd4" },
                { "th", "0551252bfaa9a9ad40235d81bbba72365f0e5d6630d4d5f1720b72a684500504459d72419d0a00c9821e15e6b2645eda42a1eedce5248ac9fe6263f9ae3c9adb" },
                { "tl", "508369386b1f722c20c612f2430bec3b81136632701d921f2db0a950fed0c76e26ffb6889c4a44a403d173c80c2855f34cdc07c318aee14b48a69a31a63bcc7e" },
                { "tr", "6cf6ae398867c45dc5ed5712c58f9c508267d19974e0bae54dfee1772a9f14023d770cab876060aea6f29eea7285f1fe172cb910e60310f6febaa8c07a68ad87" },
                { "trs", "a8055d8615e00f222be8790cf11a7989d0c153971cd2cacc8961db9f214963270a7e1817890769a3fa18f20dcd65a2ba0ec489f9e2d3b025f206a890378a804f" },
                { "uk", "8adebe401e96aadf635634603179b6e55329f0376b5200ffdbdd72d09db295620a1cc135381c58f558b8c7c4ea537bb28e7c8801abee6b6f5b8223a45aa2ea5b" },
                { "ur", "70b6dcd21bf2c43a4d96ca9d1bc121a6572aec193c5dc5e02905333decbdf744bb459cc226cf622a0407fcb35df57a172cccb3c1ca3f0b240bddca2ab172e150" },
                { "uz", "07b4c8d93eb59c647fd3fe02a6cef45cfbf03603cabcfdc862226248585171e5fa299aa410b8a16ee74629c3e026d6f6fae5ef0b1bdc0c5106c37af9c84382fe" },
                { "vi", "d680b675f6a488e0cd43f719288482354ce0a94962f4493900e72d1f0a4078053355805aac8aee34d9c2f72c0a4e6fbd4d4cf15335384ad921fffc282384a6fb" },
                { "xh", "8321659e8adb51b697177357f887a5d1634113e18c65d84739747e2948163f328bbfa1114d69946b2a79c53d5b7a24acf5d2b04e98989d9eebf3e648e15c18ec" },
                { "zh-CN", "3c4a693d2be3a6b5f9a611218620ca106d9a61243aa4ea9591e0b68ca9f2b4a0bd82993c63dfa542260dd8b74a8b3944d1f02086c663e49fa929977e6786270e" },
                { "zh-TW", "8aa79b1b4236fa9f81c13e42cb7ef34f3b25b0fb4f2c9a1e725e02585dfa8ccfff4f057453b0429b8e18abe07c0a2f3606437c5ad77af107bb8655e349e62f19" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/118.0b9/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "26afa6b0b2d32d0425181b43b11d1f1b8ebc25651f00eeb6f7156490bd4e0c021a3fa1b24d49347c46e225c865feec0fd9f0501793982283135c287610aa9c4d" },
                { "af", "a6c814aee71e80e96805a78437e2c0535f3ffe9b3fefa8597c0398f94f007247a353db41513720087e4051d49e2d83206410621442facb8b6cb3b266072437d3" },
                { "an", "4ee5c4afd11cc4c2e46f984f14339b1dba1e6279e85fcd3ca2fb9f51b321aeadd885c5019fe5f0f53724c3a27a2dcadf8c57862a09fba8b364d78dc1de03eee3" },
                { "ar", "2c0afbc88b0330a935113e42b5e2cef12f58c046a1d6c1bbe5afdf6714b1a56bf97b8265cd236def9864cc4ff66656aee2d5b1f103dfbd8444cedaac987df3bb" },
                { "ast", "f429ff4848b5af7156a06c3a249604f6fdb6db097307f9a618cc88a59b4b36991f14ea5aa12c10406f1d322f4e7ddff16f3e226895d22f6cece135c1b05586f2" },
                { "az", "eb1487712f9c88c98d365c5826440f45b53af8fc58d354baa8f539260ca63e6030ff76c1df0ef9d1a5edf7589f48897fe557539c7757c59a72570f04c82e66ff" },
                { "be", "ec48a0b8b7f6434f57f00fb58b511997bc6b7009746a05586fb1e201a8dc3d0bc429469fc9e6dd91c5ae71d18e7898b3a32dab54f7ba508aa666ba19a7d303a6" },
                { "bg", "2c785d18e4884e765a3ef9420075dd8a84e5085314665cb5a1192d0630f3dfff48469dba07b916c4929f48616ad302ca89c7ebe2b15a916d7d450102dc5c9c79" },
                { "bn", "c6d254e8373b200cbde87fa337c177e9c78799b7333f70f49ca0553e883526841d14cf97eba22d6728f5f842d9197e21b92400e3341d6669aebb8fb7e1770f3c" },
                { "br", "fcc234ef132aac154d0a09297f29497abe07efadca528427f11e04de2e068671a3a3044e1020657338415d72511dd59c09efb7d74166f018ba8e21b92310a0b1" },
                { "bs", "e4177016e7f60e2e52a57e425f345f7c9581d6ecda31f43a3c7a1953117bd3a447924a346c4ec1b7212ed1c6bd68aebe69fe1f9cb2f9b831d896c2b3f55b3f9b" },
                { "ca", "c21743193c394222b68d111884f3b543975b7673e37c054dd6f213c08dc128f06bcf3f430c0fea325bed09248c05763f2d4855cd662490e273d5ab608dc6272a" },
                { "cak", "5ea47231929ba22eeb4b9fa37338070e178a1b7f6d55a8376801ccbf7a1d19c8b497242fa6fb085aa9a23ffebc8b5bbfb0f762680172d96160293abc00549db1" },
                { "cs", "086ce7db3c42b067b835974fff9e4f956cc5ae5ce0b93f201bbe4e69e6f10caf08fb2a6e44e09443339c0085ee99782e70021f03fc8de1bbbfc3e3b6e933b4d8" },
                { "cy", "96cdf23a8ca93fcf6ac0b24f8536b45a3b38b37d4d0b0d336c9701c25d3bde4252749010a155e54b039cb432d21ff38cb881f5921809c0b9025d45ab1b9b656f" },
                { "da", "5a7829f136077aea0c5f09c76e23001cfed45739666daaaa5aacdd6fe2cf816f8abf5cfb4c0c639c4913a427c651afa9455d06612dcd137dc90154a8c154edaa" },
                { "de", "53d3492aa839ed1fabddaaf8d3920c24a12bb50ea22418a91b14ed5fdf52b29ee721d4e499db11dfcab33b4de1e868abb04d9b75f3890acca2f232756bc0a035" },
                { "dsb", "cae36307385e4e897a579a0d82b2f782d025248c393ec2eedc4d423a988ceee820e76012a619886f213dfeba95158761baa987933bbbd714a05ff02aa7352293" },
                { "el", "65c76c9a50ea095e29f3893f6c1faf2558c24a08df8e1084ebd4a273296a4dbbc60bcab9612c2c093603b9bf53d96f0a5142c27126134d96e562e4121d24443e" },
                { "en-CA", "93d19050f37805d6c6aa544ce85beaf6b9a64a97c0b8ff710472dff9497d751f8c5abfe406fc165cbd0927f7f44a96e055b5b69871555f8437454f6183a1ab7a" },
                { "en-GB", "c8cf08c2bf27937cc9ec13bfc4eb77d80fa3b26d97a104f16d4dfab08615ae20a13ffbb5ba3c6940de99a0c3ccd99a17e83054d55428bc0960973df3226e3c75" },
                { "en-US", "f321e8248ee46f8e0bc98871793d3a1b3f1e06d406c83dd940f1ff3fd55956fd8f43f7fce8a340433d6fc5d59f0561c7547148c95937b6e97bda58cc1f152738" },
                { "eo", "7373a4fb0d30ad2a9f1e06f3c24178258c2dc7004d0bd6d8f1f22f5d6532565908c20d651ada2f6b7177bec9aae399ae627aa8364d1d122dd476e781efdf125e" },
                { "es-AR", "76d641a6ea058758fcb2a7cbfe9ed0e7518a650ff59b26d6729bf81161c89296d33d8113237c43ea692b1099628c7e170cfa446180fc879f98b368935f92bc5e" },
                { "es-CL", "15f67172598e7a71559e5e7ecfd317d5e7019bd6dfbf7b991b19c1c7cdea3b8c44e89a3253667b566fd7896103dd0951d58eb1050447ee263990a3363e767460" },
                { "es-ES", "1247fb48bf9d980612c136432c2584f3709e1b4ec33f60ecb9dfa865d15b21845e268fc4148add275324f70b3e5dfeee1fd64ba0dbe1a8ae3877613e9534613d" },
                { "es-MX", "01d9fe7b21c0bf116b5de6f8e08ea2e1c62d5d8d9e84c1934adf4003e15bc01acd8f2969abb8af7a30a513be832a4cc5662d9f2cd8a2aa967cd59d4478d76922" },
                { "et", "99685fe4a5b50863473cf296064398e8f1317a86043529eb6bd1c306d90771bc3e8edbff74ca1dcea3f87738f00d83ed243ade6285d10441810c4299b7477257" },
                { "eu", "dbe93a6d8ef4ef3583c16c5eca1d2c7e6b935908f0fabb558a708a8d2c33a176f4571c4d329cb855f8bd3894e1153c37642de9eff1efa9a52944535c254c35aa" },
                { "fa", "e119b96eef195877c84603cd276eecc2709279533dd27476739d8a96412bff613f425781ef0a2852eecdea3f2a3d874c5f563c401b73616e7a1f8a5d7f2ce12f" },
                { "ff", "f846be8520cd452dfc00924874fb972d51cd956b5642b758c695146158ca7c06b2ecb3c996834043be1b3ddd11456a995bd063ccd240f3fdb06421d8da39f02b" },
                { "fi", "22dd5650ceed19ce2146bceb360524ce2d1bc0528805586a2b7bffefb9ad1de52a1f4c74590708354a0d07cde207d0a41277d8be6c63b20ff2a8099d2a1a2361" },
                { "fr", "d3bb31bf74684916c3ca1293006cf1b858f5ec1fc2ce0e59c449c5c25bac7e862fd26765b7d26c20dffad815e8103726a37421776fc6ad34bdf76c90c09a592c" },
                { "fur", "f6b77bd131118511f9c389900c59d4d6f6de059a7c0ca60a53f8eb004b8e69fe2d1a89ecc777748f935c015a1ad277e23eecba8656d5831975d9c33e51ccc6e0" },
                { "fy-NL", "9d6fb25e6ab610bf488413cc4bca311aeb1aef12881c542cf8ca3f00fa217418c8a113467a71bba76e88e681a81e6592adcbd58d11acce9548ae4907683a8d78" },
                { "ga-IE", "9c17638e9e161fd8dbf6c753670dbc6e3e333e6ed41fd0c2d92dfa72a089b7a54c9e7314754b6db902b6b3de5b3986ac40fde576eba03e233b0934dc37fd3eb9" },
                { "gd", "f4df6bc27009c3e901a40e1a2c26f0016595c573bac4d84f35c6a5f688ac50f0d7709f5c4b80ee9f80f64f44ca296a138683cf965cdb9e57dd8daf3dc9a1b46a" },
                { "gl", "2fdc62a3dca64fb33dde1073cd0df18b17759dcbf7b1f4a20345a49a9f973513732fa8742ae6f5b5a5cfcbf5b7ab3dbae5a47bc0ed70ab057897c76c01b9e735" },
                { "gn", "9136d7410d3eead00f9b565088f83c650a949d5d53150d88905a8823a0066052e1543f2bce4a5aeb67343420677e6989331d2596a2eb2ca5ba7640fa7879f5b2" },
                { "gu-IN", "d8cf55ff6099d64ace304621e9169a649264731a1e835c35a5b40baa748aefa8a41bd8234935e70b8e6aa1a9905e5a28527cacf6a8f43b3e81f94e21bfc0efd0" },
                { "he", "8d7dbd63d406072703488fd18503f38a2e82b782153d0c06d62c6630f89923115de226174ec8337fd5144a92797e906a307f52095560a8412bc3c3ad85d5c22d" },
                { "hi-IN", "2d417c1071ae8a03a69d8b3c8be490200464987685af9cb2e030afdffd291f1e72156f2cc175af7821863d94233ee900f6d2d53e83cbfdf66eb331ccbe063142" },
                { "hr", "7f406d71ca1c96945ea0dc25c9b3e19eb402803afa83bfa80e3a5d819ff2f9aa2842009939bf0b0170714222f02e5f7ac7830e6b0edabc9aaa8b81ef38ef9627" },
                { "hsb", "357419f79a32c3dbc179c62431af2ea4354c992f7ea9afeabdbb24ed00016803461feb9b4f3da755761376388c2290a9bca5ef5bb899fb355097c0774959285d" },
                { "hu", "ae90193ffe9274d31e839e863bfa9d3a188191b64f63c31f829ba2ba2b89bbb975590cd572159ad5e6cfca1b21f41051808cbd80cd85b755c359e66f0d4dffd4" },
                { "hy-AM", "78e48750ac978f9e19371428e22d9fcb9b1a57afa8d66276f770a3a60ab0d77fa5a2ae1141e325552f682be2991172c4ae1bea2233b73b401cae5a1097f19bbb" },
                { "ia", "4a0f738ae8954e155d6aa88a3b3594e54172a0c222fae77400a7e6759ebf8f691ab25034576600048f4edc9897452f1846ec47ebdc5aad8602916e7c800899d8" },
                { "id", "98af51a2297e0ae171bc388aaced2614af7dfed493c2e7212ca48e6b6d20b927d0dc549f0dba2d6d34639b01ae7a65f68da0847d13044f92c640c4fff7193189" },
                { "is", "c7ffbcb1c7357dbb500924061615b728d9a3ed3fd0d9756ca6c7cd16976e0e8ee99dd72601daf15f3bfb88d504e219e31ff1733ad0d3ce86863bab415a5e0df0" },
                { "it", "3bad4b85827064e5bf465a67a67fd4cdae70db406b95e3d9083e4aa55e3d41cfd22161e82ebe9a1224be56f9b1dfdddcf1e7267027b7bb1501d5bb915baf1283" },
                { "ja", "c3d191f27ba6bceb6ad516f924dcda0e7104d5322919add3139f697428b139d9e7a95958098e35dca1a812a12431bfca10ad0d88ea771fb59a81090fd2c4f51e" },
                { "ka", "57f3364f19e183aca4174bd102542bbdb8c04f3aae0b2031675397c663d28d6fed3c9023e2ca75cf2009dd496b5149865264f0fde159acb2f93849767919c49c" },
                { "kab", "c3ed598ee571e83949a5abeb3c6d897b1b675c7b509f43cec952bdb57f90b4361e5f98feb7b764270aa46816c1d1caef819a840694698cfa3a48322d8dfd8fe5" },
                { "kk", "037f4b3b9de87840cae4b07c4be5e6877bbf42425e4d49487c9c7f736486a296b1c5874a1e404983c59e52465b004503081f442a48096720f57d954ecef2b32c" },
                { "km", "de30cd2bdddef5acdb853011f62ee3d5db8ac826d01be9a8a9fe13bb7028e28908286396289845cb79ce5ddb3905b91c3cf5c1a9432c780a5bde547f572c1fd2" },
                { "kn", "f1c24a49b5716ee140b615b93c90ad99b9cf8357304f94d1f4a802c178bc8e7be9f9b23ad08b87ac22c3a272ebd40805f4077c6c7f40aff45d15f7e7272c7bbd" },
                { "ko", "a9762e2a8a47e485d69e9a87c1f845dedd10b00664064079afbbbcce9d27736b8b84a70e9132785f692d557062457149481bed560d536694ef7dec440d91c2d8" },
                { "lij", "f051561c5247334c7d2c631b1c9ed6315f4a3f2f6e3bd0c23c8e89ef6356cd665460eeebcd252ed094f76bb0de928ac9c389978e1d113d19e4f6b2470a8f179a" },
                { "lt", "8f1b2d785d21005859e150176329a7fa7167b58170a63f7aac16467ad5d1a9238984b22745e666fa0c2454bb879141c143396803e413c37baeaa8cecfad85742" },
                { "lv", "a935660eff7090419ed8f727f77b88da839fc39e5edfb627251702c997f2937cb984935b8d4869ab2b6b85d1979aafeee61be25a4c61ac473353207c2840c5b8" },
                { "mk", "dd9f7bce2b451f0e650b832d5150c823517d57aef38f4d557b8a44790699a23aa21139bd0d0ab0346f0de31804905a4402a7f81bbbdfb4dcfcd2956180712751" },
                { "mr", "14b9d65e1132c5fd51aed40c8a8c6cb774520cd1e54b4ed8e38610f8f5ca1483312b6c3b5f9948f8ede7b4664bf565894358f89e2b9e7c5b452e1d388968140c" },
                { "ms", "7c9c66a7413774a07a35a38e444331bfa6b8a29bb0a5c37d893ded6b50db719b586f96ee7501ec24697fd2c8d099e47f1b805a5a1a273ce17decca8bd72204da" },
                { "my", "cacb936911d8cf6a7b6dc29799846664e62c383c537bc21c2ac9b4fbadad09b0dffdb1b50bb0a7e47847bdcd5c2b2138c287689c6c717f2b1ec2e5df258c7dfe" },
                { "nb-NO", "c87d8ebbd65f22d5a26fc0786bcda22251343eebc5db43a6dd74d75fd52fe4d7acefe0e162288f2f0427681e80197c3348154428fb09c05e9f23b14ffade34b4" },
                { "ne-NP", "daf9cfb621dff86f4dc086467bf0096cc8c81820a6722af127daa39a5ffcbaef6b12fe0df6828da2581e2096e0a4ae6a9fea2a508c2142ac001b1c473c0dbf3f" },
                { "nl", "8c053cc0b0e3798ecb3c6b6f182fa53b095f21d7ff7be74166fe3729be838aab8b2006faf9b6ac5bc06a42896bf2fa42cf2ae194bb554db403d9024040f20eb8" },
                { "nn-NO", "a06a69539740d5aa8ed3de669211f92dd1cb05812eee78dec93c6814dda104b51f7b4adf53fa82bd699a1a020f8d87c7807861ab0fab79981597a7318b2110f7" },
                { "oc", "b46f48ce6dd7dab8cafbc2cf0151477bbec8b89760a533b8f6e139d7d1586387088c0cb61998da4d0c2c6ad42b48db95166b78c14fa12a8c8db5374137e32bcd" },
                { "pa-IN", "4e46e805e3d358342c39a793fc2aeaf65debba657868222602cee15fe3ad8a5013cfa8e876e94691313fc8c6373fc597fa6f0806d718054cbca5381bcc3da0d3" },
                { "pl", "1155eef1e0d53cb5b03c895d67195b80d3773625e7497c673257f88c9fe035acb8a62b4b6b743aa45e316db1d2db2606ed12ce78b429ca236e9596983d163b52" },
                { "pt-BR", "812242a447d59ce14611fb975f353d3eb71a760198d8a4e0b27665f91ab4ce713d6cbcc413224540a55c76b13a598694baf894afd0b872ceb349bd55a3ec060c" },
                { "pt-PT", "6f696b3cfa863bd2e7855c4a95152ffdb379772f6eac8345ca62529b7fa625dedb9493ae930c5e660dab7f25370f9db089583a669d145960c9734a2fe3b4ceb8" },
                { "rm", "0e37ff01569d7fbae8b45cc13a6d4b01afcc6ba72ea570f339e00deae3e999264cbe728b7eedb823b8aa17f4be3982788cea1e614f3cfb26f419f892884a1f07" },
                { "ro", "10d7eb4a98ecda568abe5c28d0321d029a949fe152bb763cba45acb8d222b7fdc251c61826053ab88601bef96aa4c021f5f22fdde4240ace711371f599a8f724" },
                { "ru", "84e2af0c1508ddec814cd147e6e2dffa3ad9101d40565fa3e18183b39942efcdd92c48a701fe11c88ff7fde079158b91d437f7131e7e10ad3f78c493c5c60cff" },
                { "sc", "d6d65f78906b493e34c2936c431f5e4f01a6c539c2b426f82ac3a91242b3de7fd291dc7332d475e2735176569535c495d989025673ef6ac658106df89ed27756" },
                { "sco", "e5d41beadb916a256aff0a78b7df03e5f992525a716018c52216795f4cb8d066d4428e1653cc338456055f21bb4b31842760f11ceb61eb46dfefba7843c0abe8" },
                { "si", "2a5dcaa893f38e626ac8e6423f40e9b7c340ee1ef6a2c0b0af87d1905383de4dd83db5b0fdb085a86184215693ddc590b9a0d5cf009675a3c9bb30ecfefb0407" },
                { "sk", "1b1438cbc57b5b07e4277bf62db47a642e241cb117f00c50fee0632b6b71d46c3f2785d59bef63538f60d4381cc817447d6e3c7895ee2fe981c25d3e8c90fce7" },
                { "sl", "763ba4996a3b99d5e7fed4ea9ed509392a424138b1e16c0c041f727d6f4c4d2fd246f767389f5d96ac7172484d6443f6e61a584aaf79472613da2ef66fd28134" },
                { "son", "826c5eda8e7cb0551404de5f265f5b081bf237d0dc91503544c66be87dbbb7f2699a845e6ca9f5e970d6a4b329b2ea1ee0c5e6ffa5a385792ee116a8ff63e0e0" },
                { "sq", "c5b961ec5c6e0a50fdf48d9b95cb3f4a71ebad0c5551060ab12e861c01cefe2fc5d1031e56f8afada4c7cf6f81c5364151842eff37a51fdded3971be59f1c001" },
                { "sr", "cc97b72ec1ea0130137da3db94cb8d37d83ede494601c77acb6708bcc54b41c38ed7d15ffb997d7df619689f2e949b9bc64a9438e2383971ce906c7abc954d79" },
                { "sv-SE", "e91a12d85e469ca23803cf41fdb48efca1f54d8e2edab2d45449ff753f684b0183b31ec76937e322d0db707d5b8a4ff472d8c2a4e6cdec7223ed7f5a64623474" },
                { "szl", "bcf7f2eaeb89a1c150f80cb734b908a2a602c4dc554c91240e194badcf449442a175a8671fee047da029489c15fb56219d30679f3a8615e654f985f347fb77f2" },
                { "ta", "0212bc5b749259da4a7668fd0f7c89fc9a316b45190f48f55c70002c6e23f760b5097157e4f385fa70f0fb037a20d92929d96cee61cc205cc504f8e48f55a79d" },
                { "te", "1de9a3bb4bb52e72515ae70085ddacfe1f49d6378d6eebf8f446b8e47931a194e580c463965d9e5e312ec300ec4a32c2290eecfb85040c2665ca32323d9e4c62" },
                { "tg", "b551431fcc9a6c5f877b8750312606257c0dd8c33b098ddffbd93a675577ec60343770e08298d3e417e67d469520fd34af88a29d0dffb35d186ec743a6c56c88" },
                { "th", "87bc23b0609bba186e6880d14969b00257850265bf35ba1ebb19008171c2d3627bd5c6bf6a110972cef6925270eab298d92596880d0a15e430f9e5c59efa2684" },
                { "tl", "6623cf88548f0df4da4d571e2bf3881d95def65308955ca2d4a95c5ee7bfcf243abb62fb929fe3d468236169ab9ce5eca7987bb87eae5c5dc139b65003d0e938" },
                { "tr", "fcba9e5673fec7642e74ac0859a1e7b3f3dc0064e356ca206332f1b9910456ade546db7b22e523e7c772f85e86d108e468e8c3a63c2efc4225dd903fdec6eb99" },
                { "trs", "67b9dda9260063d2a82b6d7b7e361c3267d611245098411a3c5ce0e4f26480dad699b14feb8c8476db2d00d94a9ce8503a6716c30858b3ea32caed0f3e723fc5" },
                { "uk", "f951809aa87bd12afd44ea346748d878e76475ddc3d95ebe41c2782b365f90f7be88aed554733e823a86180303b3d6205bd6c438e9f30714aae1632c4c892f59" },
                { "ur", "cfe880acdb69c3220bd21d05fabc27ad260c583f654b5289f883443afb17d99f7c3bd7847badea295334f5c8b392cf469ad5b5766ba5a3b155d827c25a41dd18" },
                { "uz", "9f58c1f8fb4f5046170910bc6c132868148860404727168ca1b4a37283af8bb7c3eb6c9746a39e20483f3c994685e8e1038d074fdf2db1e30f0c7e6bbe6e88dc" },
                { "vi", "788abb7d2c367914544d0ddbd10a8b2889752d77bdcc1bcd530cead301171d2e0bf01f58c4d89a8c7c0e788cf8cbe3e092540b70713a4ce890ee7b24e7a4ed87" },
                { "xh", "4ab284218f5e2526f30fb69b884571aeb7179ee8c9aa30c5c9f3120190d49dbfab0a6ed6ef6b60890dc346e5e7a31825bac2017109303fb80af43ea2f43a029f" },
                { "zh-CN", "514a017271e16f3b940b9a5ec4c864826aa9b08440d724e11bc8fc52cef7da177069a549df8aa9f7a4fc74d3432e22dc0862a2903d89b0bc9f383f150cf33e30" },
                { "zh-TW", "af41f172f234e4eb332afccd5c164e97bdb6ebd7eb79821c90afec29a7813498ba23bc0b1eec8abeadbf70135d0e3c33668128a9d3d84a38da47f9096479bfc2" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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
