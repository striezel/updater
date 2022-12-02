/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
        private const string currentVersion = "108.0b9";

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
            // https://ftp.mozilla.org/pub/devedition/releases/108.0b9/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "91bdd325ee1cf987f95c12d57a80692c6b59a8d2fadf02e15dbf6f4039026e2190dd8d10f11915b78a8b305330861d5dc9052ddfbb2eba63a9814e58e5b424f8" },
                { "af", "89c8b00c3259bccb1264402c679d1b714c4aa08c1d5854bcd824345ea9b124c471a59b17c7a48fc816b4c7ab2dca04ac2a34f8d915cb7e818f4fb7fbf11ae59c" },
                { "an", "eadc550d3e64a570e04828f131fa492f7c5c5b82f88112d72d464e828321c91fd0acef56352598cbd45e5f5058cfe1e66c2a3bb51de95ea960cf70d15012ea83" },
                { "ar", "a80fd711ffaa331582855a369adf3d9c680facf3a47eede7b0ad58c1d58d365652e65b03916f82b34cea6748e4c960990d07ba85c7380f0c3252a591d4ff9d24" },
                { "ast", "aab65ecd1b595e4d80f58076242866fc5724d0879acec5c5fa0ad5d5005ed8be195ccf7ac5bebf8f1e1d46f1da02cb5afc387cf0622634f5229d2b6281979eef" },
                { "az", "0bfb82ed3a5a69402170666ba01aff580564120172be47da8b0f115a43926c1c650c7be27e0fbdcdeebad9b73f4db873d3530e7ad5d0b47d87964c9754e12bc3" },
                { "be", "3cb12c77bd3f41fd9cd71b77c860971dd329920392abbbd9039aaafdfeceb98104ae446919a326f2cab44d245c437fcbf842aefb76735707ae479959600e3a5c" },
                { "bg", "f4007bda7361d0f3754185864d374a59317d5f0d53572938d4f71ad5b91e37377a2c6e461ec9a6e1fa84420a419eb1e7a7f3a1f1dab7b040152eed6602ee300e" },
                { "bn", "d4c020897726a6f36f20db3ee479b7a1d4f73a2fae70ff4393e29e08e1d2648a8f08593bc89d92e2e09068ddb217f704825a22da1119e633c836bc145940d0d9" },
                { "br", "f457a4f01dab025c6138879d733a82e89ab2654ac880559eccfa3acfc75ed36a67114577292d771c56d7aa1406b9d54c029507a0e3112cedacccb126a5922e9e" },
                { "bs", "61ddc242247f05d7c516bac921b38c739c7ca7626f18730b238ae5b1b281d80dad03f2623d284574e7c3b7d5879dd1f2ddb8697326b6ec83b4553358925d73ce" },
                { "ca", "f855a4469d0ba5cd9e4b0ac77b97e57dc726fc63ed63964a8c78fce26d938724a2d0685a6fbc0f3e50bc4c56fe2d98957e3331db79394b224edcd5743172a96d" },
                { "cak", "a3b9c8f57727eca7e991e747244d0aafaf6e22b968bc393b8a17f848196c8bfc7a1184c620be12b34acd508601d54eff11d9b18de1339badc1deed1478712e05" },
                { "cs", "8e57eeeb357c5837460cc3f2e8f892e78393b0443d5d0c6fb33910253c869ed2d6748ead1f5e563fe690b8f148b469e87eeebb005dfc2a154d90bdf7ccb305d2" },
                { "cy", "5dfb81a65e5af3a725fd88bd42d7ddf6f79036852868325b5ca0a5412e48aeb947c69c3ce8a2a05a5282b5ac47ccf78e0f6acbe59dc0247f121d90c912e278de" },
                { "da", "3140107a7178a0948d90fadf62bcd543c22d7925c294dc6b33d6952a8fde0a24b30637ab52cb62beacef5374213f2fd410c63c98108341fe513b8b8f0efdc3f8" },
                { "de", "6ee6ec89455f3e5841d301715ee8306da7e029f0ee2f1a61089d70bfcbd4de1bf136a48326765059f71bc649c4654482d557950ff6be681d078989983a3b37bc" },
                { "dsb", "f668fcfa415873ff4ec8948fee22c029d8012f568be4f88a12c363355d8dbfe1f946b456e4d875946214ea3161669453377173da2124eec60d4adf748b744cc2" },
                { "el", "fa940affadfc8e95feedf5b3ee9ddf4525a52704865376f8752caf58e987cb07431c7b58f093ca56973d81b9fe78377a6418ca8966d8836bb5cabc66bf8f1de2" },
                { "en-CA", "9bdc39e1ab721709b1bf55a73d42eead6e307aad1fec8526247a64caa373a6f34c4f4b7a53cc95ac25ea590f30afe9b4f5f82f42eac4a04961983777a02e7ad2" },
                { "en-GB", "67596b690fd157105e8e4f73e2af75dda726530cc98ca43ffc2166586e8cf2b095ad86ac7428dad09d2a299832cabe38a5297f076db1c76b93df4d7546a02a85" },
                { "en-US", "e978d167c1dfbd47888ef86d6225d249cc330a9c399bf3554a56ad17e9e95217b92383ebcc340cb0cc64ecab209752da121b02ca5ff8a897c5bce1251ea9af16" },
                { "eo", "7ae7ed4e5fc8716c836f8e5bffcadd2add88e2714992cae4aa3105d1c50d060fb2dcbc95df18c91d9b76e59338eedc111b124adb252daccd9316aaeb5ce572db" },
                { "es-AR", "2a0d291e81d8103f1644ce7c2ec0208c78079d63bd4821dfcb3b79b8ae1ec78ae7bce15b51a10161218e23808e8b9199828a0c5f6c7ad2d64278804c313f5612" },
                { "es-CL", "301d8a20b820c78f2425a4462f1f90cc07942c7ca646852ab37c3f5098b59367c5d24c4cb1e920ad31187f116f09a69373511290802610ad6d28dbc2b65253f2" },
                { "es-ES", "a400ed80d630d5c4b77d27311fe945462ea85e3a1e95f66687237d635beb606ae02ba2eaf33d506c5a5e2d3e5ee19c02d76dc13e4b5a6f01961e6b49151d35a5" },
                { "es-MX", "e7b310dbed433ea56273fbaad74ada79d49f8561386c924c276abfd1338a4e311bf73c3f1509c8d7a855598f135f477c98138091e96e5a66540d2e08b7f0a70a" },
                { "et", "b61f1eb5f392d7f196eb6aaadb1158ebefa0c090824c7ad81fc83b9d42c33c28361d24b6131800ce1aa7ead7bdc82114e98f37df2a256c09315388105b9eda3e" },
                { "eu", "4cfddcbd6d1ba9f3638d42aa7dd4806afabf4e46926dc9a25818f04428fad7a801d375d9e82217a25dc7f9816606104f44b35977b335465e4af315c870e2077b" },
                { "fa", "c83b7bae70b4a163eeb92c68c6d3100847c160c8bfa10347d37653779e90ee5514e7dd2c0083dac1c1302ca91889e846be4c3fa7ba7245b827a01a6ced9ce579" },
                { "ff", "1cc3d013a6cc75d3ceff1e873b2e942a824338c949f7913df58d0a7276643608aecdb8208e0aedd84b813706098795eab74a25afb2ca2fd1b5d4292e1cb2aa5c" },
                { "fi", "4e032777341bdfd0e2c1132f6422c37e3f3dfcbad9229cd91b6477b807882102cc4ce9cb293ebe81670e0f4730f9500641fdaed657979d9e75eb3bdc4d147c0e" },
                { "fr", "d12a7a581fcf45b951a28ec817e49e58401fa3b73d1cfe662e9e01ac3836758697aac5404f92652f7b71ab94048dc639397034d265cedfbb3f717876124b74fa" },
                { "fy-NL", "f0c0a673f3c99b481fefa8bdb2239bdcb9f1c8b38dbd88d399cfea982a8b839c04add0f718d7f7cd47a8725cf3a582e99d1c161dc0c325cc225627e93c7e7a92" },
                { "ga-IE", "1bc3a8ddde275acd2c721a2e73afec5cdf149412a64d0f5589afe56d3bcc54007eedf67a6417abe62760029d38efe8d071168dfdbafb9c22355ddea824d36fe2" },
                { "gd", "912efdfb05301d86170069bce6331564afeac45aa5686d7bbbbdd1f9fd1c96f5c6e0584aeda0aed3f5814b8f8923028da7af640fe3514ce8320dc941e5ffd9fb" },
                { "gl", "ca11b86c4215eb27a72cc38589482fe0e286719c8497b153f4d8f2590f8d2a0064dc1ebfad8a23114351c6d5376d6f3d864ff434c177a784bcba5b424a1b71b0" },
                { "gn", "903dcb5a4a8d1a5b9ddaebd026c8a580a48bc2daa6e187a0d4db4361fb74718319f49ea6fef20ca603d23c380f7b84afe88f0229bc2b078fb54076b8445a5c82" },
                { "gu-IN", "f6b6d05ae025d4bca11364a7a79784a86ba58656c05c1ebab3f9e74d47019f3e7b9347f45ec107ac7e68ee00a176c8b3f3a2c234a5e7d1f42615d22bbde5a161" },
                { "he", "7c4bccc518329c737e33284cf02bc3bed7b910f8b7630922b183e1eef2a53a1a02a5e7e8dea12d7456d6cd5f7cbe57aa1d8049bebe5549c7212cfb61035dc9e3" },
                { "hi-IN", "b8781d9fe3a9ef0b39cfa4ca607eadfd67de8fefab1b09aa62ee6942acfcc40d599a522a6aead9f217d6bed8872312c653185a7f9e69f1364456f766739890ec" },
                { "hr", "56d20cc3f09816d41a846cd0e7e6ec64993ed4d56842db68a651433157f44a126384f8f452cfea13f11e78c4df3c6c89d5050bf6d4f12a6fe18b0fbc8f760317" },
                { "hsb", "302a692bca6d006d6eb86130f41270ff5886c36cf00355a4b67efe626c8abe1fb4e41ae69312dad8a45a3a3b362aaa881cc72b88f9a3befa4b7ebbf630e110fc" },
                { "hu", "46cc05914f8d0fc961e3b00b48fdb42bf22fc8036126abcb83629211b5745751c67c91c5a6140eee4c27fec20d3c3eba7790f654a2c65e9a88bfabd37cc2d301" },
                { "hy-AM", "eb40e545b02f65759e098a4a2713610a1246239f532ed64b76fb611c04637cef94adda1d5981b167e9825a6bfe3cca3a20066256ab6ae426575cb92d083cefcb" },
                { "ia", "0bc1bc17b0cec2ae3a201995bc78ad3ff759dc2723dabdb920f08e9f15a44d7f1fef44b49081e9ae171085c6b15316ba215eb6c958132ce5a29184009c2dff3d" },
                { "id", "4fa5e8de048fc03039d40d0f8ed21633fa2cfd61250fa51906ff9dae581439254c8cd894065dd5fed7113e752b17d43debb73202fdf7727c7ee7149d9c27c7cc" },
                { "is", "526b420946e0cba39a8b320ec45333b3226df038c0be737d5cb6a9f94bd024c583d6921aacc59f38cc0976bd5054dc5162453344a4a870928b3d5490c38d997e" },
                { "it", "baa4ed458276940bba8a982182319e0f126ee698dc4b737a77286b12ec3d237b17a2e2b8a1ca56f0d222bf3334ba1b9952a2f9cf4b7eb18fb22d33eb75212638" },
                { "ja", "42cd95c7276ac86b3faff6bd45f3144c5e8742441b54c1375c714c1fb46275deadfdd2970470e9a4fd58861438fc306db1ccf13069a40228faf8e509e1b403f0" },
                { "ka", "14fd7962ab81c7db606640df276b51eda04225514b9ec4a7c607c6286c17dc97fc426abf30feb962a1e7389552d3345b7cc13b223e074459aca9c1d9ca5ba881" },
                { "kab", "e58f14a0f1530f309bf25312a36edb0bc110219918f8e8dd33ba03608a5f82233c611cd8388c0e491a259f8ef31190aec4191811af4d7269ff49930b0773ba18" },
                { "kk", "f7e96de9df77466448568e322e1ae4ed40bba66e5c6f7df1be6501f54f35ecd2a6a0136efd9be2ea87273fc42f55943d0fc8d7e524225ee2f178239d9fa8abed" },
                { "km", "b141b1b86daccbbc05d901d475e341438c6f3e43785329258b0f138b1eb9fb27681acdaf575dde5c72a38431349fcaf8e75514e78e7e99d2f9f8f9e9fbed37a8" },
                { "kn", "caf6da71be2ebbab524dad10e3c6b8363a2c2f14b0651c94f15980f87f44fb25baea70dcc2dd76eeede0c1426cf4ac81c21f7ea50360aedb4f70379c06eb94e6" },
                { "ko", "97e9727b5a74f940f0f234d692a17d5cd1a31358df5d2ef96b138592c4dcacdd4f52dc772a2a1600880b659288bbf4b35ddda262f49f95e8c2187b2f4ee0dc52" },
                { "lij", "e114939832122111e96089f1f9cf70cb3847864e224928071fa61f60c544eef225711eafed88de187f1e29593abb8fa9e5d6de99b281982fdb8306e902ec7a8e" },
                { "lt", "5467ac530007f96a7f7247b1d24fbe864fc8efb61b9689ce646f003e4d367a7a90fe979639e220bfc6921736314507ac8523fc85a8ff93b642a8ea91ac14310e" },
                { "lv", "b29808c4ab8d905e304592f29c401d6abdc8c2b440f5b0994a4f9b2e481fc0a9161bff15023b2f3cfa0cbf198d709e71360a241b80cce39e9efc59fa7a412f2b" },
                { "mk", "2cd23a2b0fb2665f5e29f8e9eb6f1deb3c7165a37a9270ee24a20f38dc113672f506af99a00ba178c4ed6deb0395e4ae43448d5fa8e09f77b4ec43b32ae42aa0" },
                { "mr", "1b78cc5ac09cabf11d8e747f193b730a5e9c412be7997323535fceae64143202775927d2a4595b8558648eb5b44796b52ec8414caa5fbb8ae2d0d91b6224c977" },
                { "ms", "243046c21f542497c0c28207c86403e29ee047a01ff094aef01734b16666533b1d27de6fe6ce2d8627f0cd92cc3670f09603ebc87541654a921703a7720669d9" },
                { "my", "7caed4f6b77933a51845a58237085a779f60968bc87e5595bed42eee6c245d025faa426d2a031e3ac5f0cde331b396aa910ea18d2c250fd41cd44d6ce6075b29" },
                { "nb-NO", "5420e6e6fbee3472a1e6b6fb49befc9d2122c572812ba14fa4addf552d74be891a76a3688467093d5e2abe544df18a8de6459e9c968834e4525ebb1c8413f187" },
                { "ne-NP", "2c30c33130106dc11f2075ac70c9fc43c1b6a400265bc1f5adcf9bcf4f0f24362026662669745e240ea60be0717ce1041094e847cfbcf589be488a8f1219992d" },
                { "nl", "27e3cbc922d73cc8c5042856bd38f96601991a1b0d9858ee7297a5460ad07aaf52a31a8d5dc1380712f0bb96c0db9926b0d4df3aba1a7b791ae2c0c29ca306a6" },
                { "nn-NO", "93c68db2452acf8cf3039fa6a08cc3c42c0a21cdec0eb12388ad232e205034fc1a06d193094fb1cd840dd87debd20bbd88010c7b579f7640b99121f0024ee726" },
                { "oc", "8f2c02bfca877713bcf46c64dd9a5e98590214360fde61123afe1269a8a71c1402f8d11608cfdabd88dcaed185d83f4bae433dba458266c8349f2a5642c58a54" },
                { "pa-IN", "9865c5bfa0f879ffe21680e0d4d3453bc793c90cf97d63d8db55c263ad632f1536efefb4255b49f1c13bcb002a4752782c5fb66b4eaecea5124fc12d2d00d956" },
                { "pl", "6c6d0afd84fc0e1158d68592559f9b64b29c3c386c1753d27bd6e8de6cf6a03b90113e0bdbea23046add2d387470f49d6e5874d2723ecedb6dd2a9d2ace4f674" },
                { "pt-BR", "b346bcffa364356c3d1230b7b5fedbbdcbb3deef7135395c1023507bbba96de528160b3267c01fa7e4de24918e9b5d8f1d269f72a062c9c32e0a36ea9ababab7" },
                { "pt-PT", "c283032baf337af6651293fd3f8e20edc56feff47091b0a0cbfa7ee243757562116b1e22b1a1a35cf06aeb62579b390190f8e3ea68fd3e887b3b908fdb5a9004" },
                { "rm", "9951afc1993fad22d9975c78d5685a0a295ab7aaf524fc2561537015a8e97e2559c6795b178eeafb241e0982d84696dba1b75bf7b1c2323ec64922ae274903ed" },
                { "ro", "e2be9879cd85d6e62f82f18c6d08774e4cdfab05a5a82902d1781ae832d19005dfb45ba56214320c7078bca9b5863b636570b21c7f310116c608c72d6c832e81" },
                { "ru", "b04da8cf2c5104cb184ac2ba66c812ab6d2d03c2f61c5050b0798cd0b176bd2bd6216d30aa71b2291af00161a8af14330e291e1a5a2d4ed02b1137e272f22250" },
                { "sco", "3a9a3b6748f81ca651f5809982ec660be43d17499b9b91b10185be12daf4ec89508edcbe443db943b9657b0184076db5106d1de980a8a5c43d0edee600dcbffd" },
                { "si", "d29d1e36664b030d83f919289c3d01c02e3e6e8eb15206d7713214fc28afa548b7e2b5146af6cc4dd126b48aa3e3fba7e0b205e82d9b010800c24948928c5efc" },
                { "sk", "28db8828308cd809f14a8e966ba3fe8a5015992a4bcaf2f5fe1fd2981f4831432d631b01610461f9c0a7e4f7be8b2de94f686fee80506dd2abf1d703e1a23d2a" },
                { "sl", "776b6b2ab2e194a10864dd16dd87ebf196fad7a5ae1e90c830628a71faebb41c22b95500b119fd7b2118eb55bf9c6eb0c1a35d92987e27da0f5326319901b141" },
                { "son", "e61cd1d3da71de88c29ff105d2ab21029521ce8c87e7b0e49520b32b85e2971fc2f5ddb4f49f2c722fcdefc6f71f44d0225f147e8ad1a394660dfd512624b67f" },
                { "sq", "1b86357f564430b4ee0bc8f4f34e775402127ebb40621c7a11c3fcd46294e49b674d5df86439bd17a410cadc9eb06ff512d2377107e59c6759c4b60f7a7c57f7" },
                { "sr", "cafba906a97baccd1fff62492ed6f02d12b3661d6fe5db756e781f73b934dfb1965c6ac30113483c6d39544b9fc0364ad490a595e1059f4cc1764127c9fd1f69" },
                { "sv-SE", "bbdc2c668b2cc1af47e12edc6b8fb4e95bbcf6230db4a8b5e907b770213a4f80defe8519239873620c0ae185e68bffd0ac9209153442e45d6b0ecab9234643da" },
                { "szl", "c417d4bd89fbdcf4bc464beab1c4897f62d9a3c1127a9ed36f3f0ac69d55bfc7313e4d859a6cdf17d0f6735fd2bfcd020afea0b5c8b7b1b041f3879235b46832" },
                { "ta", "721289ade6707c9ed9c7926bd2b3c43af0754bde7b5d6b94239389ac102339a707e44f406e8c906d5985f622375f8ab630027548fc62665e5f6ae80c8cd2ab83" },
                { "te", "46b22c909967490377facfe801430b33ca2778197cbbdcc17648edcace7fa20c666e14775732c7a16c5134c24a6dd6922185e49d4bbbac2ffc82e642068807e9" },
                { "th", "ff9fc33ed9c6439b38aaf8919e79229f6386530d6168f8be9ec12a321894bef833b58d349fa8603cf67a55641af5810fc233a16f86a981e4933d482a92ace3ad" },
                { "tl", "2583dbd9b16910fd5f8515d8b4bc53d8b53351d2f1ce43452ce2f1b1101ecabd3c221529331a6f62d93cf841469797e08cebfb1e92ade6e5875d8820f7c20961" },
                { "tr", "3e4fb90be6360d8e7112fd238d24532ca1c607618bed79adf194f945c7cd576063ffbaf33983508fc0a71a8f4715fa8d8a4ac4aa118057a10e32343ce8280c57" },
                { "trs", "a46207095452df8970c0e4dc7fb3947d5e81b32b8326c5197507fe95e5f562a3ff3e29bf7e070b869a880ef92d9bd7326117cc4814f672329cb0702c8cdd3297" },
                { "uk", "e6bad9bf006315932b07e77ed42fad21ea551cd3a843e0848fad23891cbad1f9af1b264df4e310e1399b3b5d96b43d9a5fa90a74da71f87b7ccb9fbeed050004" },
                { "ur", "228e19228d7d6a109649fe3613b10bd08b136e0e43e333d3d6c9388cf4f09f2702053a2df8d35c2d18075836b8f48c4dde9622d57cc9d97a87fcc0fed2cd5cef" },
                { "uz", "51de6f4e4cb3807d3409aa7cb24505a713d282c49d43e03cc866d9837c4d00804343267a5ec30a2fb3f3dd27a8ef4f9f66eb257d2cc529aa2ae670274f287bc6" },
                { "vi", "2ade8dc2ba3b77557f24eb995603c9ac66ca1b641cdc9cff9431c3d8452aeda3b2e89cd02a6cc0d61310c96957cea5a088a02b65ac52787910bd5f174b88de93" },
                { "xh", "15e6a0be2fb653dc0c6a10dae0134754de24bf6aeaedb7c3febc2fe2770909c6d7face572920ac5f0c4615ca277990ce53e67c178e99deea754c325b613ccbf3" },
                { "zh-CN", "172e07ed47726af6e6938a62612b62559c336d62482cda7b51a7fcf12cb09718947ca39c8b74bd23dfef97dd6367e320bfdab3f2a3ab033e67a19f5f14961039" },
                { "zh-TW", "fe397bfc8acf1cfd88525880bd653c28b63e9d3d62d2d85b19badc4fc34e103123ec3296a5650365354f5576c94e7c3cc93b4cdb9be5bb40c4d40ad6eff9ec20" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/108.0b9/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "9089327c7e384874522f49f0f6502a6759a707eeba1a6c9dafe0d31b26af499ff13e30ceecc7f4b9ddf42d19679e0765967365aee5c7fadbf1b2d18028f9d37e" },
                { "af", "376d3f75c20c5d0dd1ba2d890c4851fa62f629da09cca637b648f820948a47b4cd3d01363972c6c659fa696996c2956329708da06a257322a23421002fd0338b" },
                { "an", "429c315658bcde7f1623fd87b4f56e0fd194a45ee459c2de0b69858f7e6f4f8384cc62b7738e5ac63e98c3ab09b6d1dc0162d0b44d9d8dc0cba0e7e27759168a" },
                { "ar", "8819f87449fe167c9fe8e668ffe697f563c0f11ea5c2997e3d076ec73f6c0cfd656a3c6e5cf6907291938c19d5dd908e92906dab813a9dc6932abe0fbb96bf34" },
                { "ast", "dcf1c657f80416a652aa5db344b8690e04fee00288907e51d912416cc1184a51ed767bb17d77779069f7837c8fa94ddb12b5e7cc1d2cbd0ac3a31f2d611e59f8" },
                { "az", "a3e1d03388f3768416c3857a9b774900ec18c70ffe443a431c2cfad413a71fb246fb2d3cb28956cf8910a83011dacf87aee8150b22f78d4ba54cdcb1ca36dc4e" },
                { "be", "7df4c37125984b54d52cf8587761bff2b19fd4a7e75bdb467a4128ab1f5c553ff686dd3f22498b599c69c7b28406ad5b5b5ab67b8f6a22354e1dc458d6fe9661" },
                { "bg", "1f858a8c3207fdd583a9fa3f10ea5a6595f8c3c887b0745c432eb42a27e52d7e9ded40b6bc701f8ad967c9347b40a785506b3a56d1f2f4bb6e59396051de0a85" },
                { "bn", "f238b9956fa1572a208e0d3f029bdef802039dcb8b8e4c6b80471566c30b82f418886247c18394b1503206cdc991d7294cdbfd00b8ddfd6e63810b92efce7d8d" },
                { "br", "3bc48e062944ec1d83a34ac96899468888548a54e791f45ae7526508270a5e167c0b619a492db58831ee1eca36e20403291b0b3d927cab6e158f6ebbff17b2d9" },
                { "bs", "337c61ac334ed7597fd7f847a3a7f2f0e9bfa5be4ebcc018a60761015e3652731b7c3c6f55f42bf47a3fb0c8199c1ec7179d23e83a55aa9312937fb1f9f11540" },
                { "ca", "7cdb16ac54706ca255378a6f735eafb0c81332257dee92ae520cab7177a26f7dc72daa1ac96768c2f87abe514c0c896a1ff2af2920aa0c8722a9d4afae2d8745" },
                { "cak", "f4043961763a74d1285e4ae528ad69f04ccc4b41a78da78fc4cf13d617c67a7f451cc173b693ef557393006b66b0323e1ab74c4f7619bc5e89c62c9f9b8e06e9" },
                { "cs", "1298f56c4d93e06b98a6a7703bcde2bee01c6e5d668df7b425b863d6eaef02e3492d1633880e5b8fc84e0d20c14dbc04bc2ae59c7b428ab030712846c474ef82" },
                { "cy", "9ca79a37eaf3afb9554caf1d86fd61119455f0ca0a731ec5329005f6b60b20f8ef1a48ebca24c1395b235207122314ed09bbd62ff8c13aa7ae547785ae4d74a7" },
                { "da", "8fa812b65a567dd1734395f827d608b432cdf90a7e7323be2ebc06408b77edf56b9ea30af59378e0e32878a9f4df3b41f3d1ba0c9e0c6b20e3ad793786144947" },
                { "de", "c8dbc4367b0fb23a2c21294167b18466b7c07ab6a335db7231e11ba504bea25612927747214ccadf18f9b4925cb039d3420e2e673a95d3d150413b5b1e136e50" },
                { "dsb", "61bde39ea0e15629dadad31030f5cba91cb0af87291f150ffc6eaffcac18c273a3e7a241fda6b6297f04f83687270fe0fe8fc342808b634c1d1bb6bb020688c8" },
                { "el", "21d9a40baad37ca3628b11b7b76ea9108efb26404930dc62360301aaaebe274a7b2905ce9dc590f06ada1951e516f2bfa17153d88434b4142436b381fb7eaf1e" },
                { "en-CA", "e350131789a70be149112947a41a7ecd815abbbf9d37f92154108813bc89b752bacfa3266953f3062ed6ffa1bbe4a62dcd98cdaadea17a881354ea3fb8fe370d" },
                { "en-GB", "c850d5aa0bb4dbbe4165f0cd29719dbbc7fb8ad6615871ecb1071db9f169e2d79cce7e5f14bb4e7a4feeb38f5a77944a1df95ae5da7863cdd71ffc09b47af813" },
                { "en-US", "d4ab5c7acd1176b6076cb8b2b26334134044b0f73c4c0d560acc5db8b2905a7435d21a6e5ed5afd75dbeeee9fbfd4007ea5c91a75233f2b15f03a0cbe00ceded" },
                { "eo", "111b78d572f8b34c2afe09595d6bd8349b9e8417d9fdac283fc9fa758ba60b52580ae6d7bf496abece1b7a7e894ed326f384ed992db06c554cc4ee030ab12953" },
                { "es-AR", "dc299b54b94f7332453e18f94eda126a6f2edab8145f2a1ed1d6b796e6d154de0a24072f038efb0afb4e1de00756763e685c31da6035432234c49abda23082f6" },
                { "es-CL", "a2a49527e6fd7098198d21549df1e529f824ca10ca5f2c6b5119ce1248bad454bbb66ac0ffe24c2465c07e2be9ca2a765cfc4d1f0276a0c32f0cee3b0aaf7163" },
                { "es-ES", "23a67e68591c86f016ee9842e58d8d70519819e00798088ee9841ab8d654e5ab9f9a7bec1d411b4fdee50f6467b17cdabf688cb94fefb6100c7573e572e62198" },
                { "es-MX", "ab0d6b74c1403d90e35c6865075bbe61cadbce9a09072bd77965a711a079689a59cb0c6db00b62f66ce17742477053d53579a6356c79e664ad719e489948398b" },
                { "et", "e1a6dbd1d4cc8e010ec535a9c58954b93de92f243460818e2f4a08db68ddc83e2af56fe8977e25af4113c1029fa687781e5df5db64e256a2def8ea8f17b51a63" },
                { "eu", "f4ccf5479f901fb9c6db91ade2f763cc941e088d27e486458e3b5c89adbf35a90abfdc2f7339c4fd4dc58eddcbc00fbcb86f8a6a137af5a6d85fb8d7e29dd0f8" },
                { "fa", "840d01b2a0bf062b13fc2d544cdfff7bd98090ed144da6bb7dd492508833c94daaba30d0fc4b3d175c58e39b407b7a6ed046398365ff74d97544a565803f78a6" },
                { "ff", "b5c14e2127a91000a7d05f4f5307264e578344825498090324ecac6f2d1bb12b8566b90f36e4326262f9498508d83494e7e2f831fd56bc1c630a90e731766736" },
                { "fi", "101c2d719d9812397b0c39168c008d89a038b2dc33e40457b98415e06cf24d4e413ad4e9f79c9741b74816216cf64f2acb2c94145288ffef037f6df6fda92a53" },
                { "fr", "4a3f255699c40522deeba3cd9c585a1d66124b73f6774688dfa8c700335e91331d3af2bf3fc54ab6426fefd798b4050f63108f6c9d2e5dc3561e05764d09241f" },
                { "fy-NL", "fba436b2acd1fdd73b9965d4493efe09a59ac56ca583d4a7248d93dab320c7bfb2cc35a4cd3a5d84a1eef3e1d5b6e5232554f3580643607487a2006afb241c50" },
                { "ga-IE", "90066595d2fb067fd24d234a6621dbe22b70d9e417eef4fa5d8bc4fc6936cf7a162a15ab84736cc70e3fe66c2138cebb2e3ea26482a1e9f0b70d55e7aa686221" },
                { "gd", "c27e2c3947e3292b5c56f85b2ff5960cd7db5bcb76a1f972627dc88580f4f61a28dc2ff06b0586b3e9d317936f7b360831a615ae29158c226fcc5586bd6fdba0" },
                { "gl", "af01448b57803c62c5a1a6bc7e1345c8ffa39b203a2b391cfa6771f5ef77c31caad43555db3326bc978b3992173944476a6737a3fde668408adc82e29bae4628" },
                { "gn", "46da1fbc8e523b891ddacc9c7f0eac545794350656f4629c0f06fab763c7f1226c1366f9c1b92b3f37d1b22add6b8a70f3982a7bd309bef217941650d11affef" },
                { "gu-IN", "bdf47eb555f195626f5c5d71d7ce29be1ddaad33afa4fc52ed428c4dd8705baf497a3253b14f7bb2779f953318d5c7f4b6aaec0dd18f43e88cdb8723952c297d" },
                { "he", "4124d907a52a8648fdd896984dd56d2380ba245cc686a4a79c014b62c7bf5502ade97bddbb01257cdd5e3378403c7897e23230ada2b69b85a3093802ada15ece" },
                { "hi-IN", "f96616a0a8cec3e3534a24964d7c3c61d8b25273de8b1c4828764e48ff56fa4d42fc24fc4acab0b559dfadaeeffe0fa9c4be6ba7ad9b009eeeb9372c59eef434" },
                { "hr", "a641d070f69e5ab5af2390673bd26a56874df9929bc670b18a9fbe726d58c3f776f396950c18d7a58bbeff02191568f0d89b31abd0594b6aa3e1dbfa2b596cea" },
                { "hsb", "8050c181c6bfc7a2173479e7d4243148417be1893f2c86d319c2c52f4aad8e116aafac9ff5cd8edf2126a3f381548a3a690568d7d1b7ddff881d1164a17de545" },
                { "hu", "ee1230cc572e8011b100922f884f880ca70635460e12664e04fa187564bf2b13876eb04a9bd7e049809125aaa29c44f1f40bb1f7a0cd8f34f74f49c4e704a3be" },
                { "hy-AM", "b34b737e8f1aa577d375a67924af3fbf3a91924ff68a07fdf5d9ae96cbef289e5042fffe7ccbb7025274d3721749a433a87c445a8e063f5b56b2b053654739d0" },
                { "ia", "95343583c16bf261d4ae267452c86ea4afa2c521bc911ff06230c3184fea71095df03fe7f758acf20cb58fef491fe367f6c4cbd9c10c643caf4ac139cf4738ef" },
                { "id", "a4af917e522be6de153495c136444a4f69ab39697bc85e0f2cfade25fe2ab901a5fbaf20462362e8edc4d9f5ee543449753b3e37699464b6deaeb7b0e0b2baa2" },
                { "is", "04f76d07c781ce12441dc25218c97a57065a5d904107191dd2143a48eac8040bb4e8ec9adc7a512c15ae766f782add1cc1ab80bc2d2cc21d1f935c1866962145" },
                { "it", "60dbbc1036ae2166634794f8ca6e34db6fe2cf3def2ae5e9535497fdcaf069505046e0d96880387f3aee27e8840853fea90d9db820584bd8759075b5e1025a77" },
                { "ja", "19d2042e5e7333fe45ecbb1750ec622b53ef1009a2272434a948a0930a1ae0e835980d4f16f783f972b86d8bb1cd169ca412f070f268ee16cff165b3d126d001" },
                { "ka", "79cc02f9d558ebe95e1d078d243e4db642ac3affe7782d7c013095e4b7d79a666fbe6e231512bae0678038fd1322d5235f40b47537d08350e408349d183fd207" },
                { "kab", "6acff5bb68039ccbab86e574da4b83690d63f2d6a445ff0706eb1067e6b40c484c6baf02e39a3d49824b049ff86233814248f523e43add61d0f040d7a3c8ee01" },
                { "kk", "d8bd583abf41fceddc82a4ef88b604b25cdc2ecc7be6df9d979e3816753ffac5d01d74b8d012d6756c353a45c1e3695888c72369e3ef64a21a9e3595f107b1cb" },
                { "km", "32f137a797dfa1d421d649e85550e71f1b41ab956e122b410b8062b25eb6e589d79fe1482f41813b007d7dc2ab35e0f7d459820cdc23ad9e0055733cd3cda3de" },
                { "kn", "12a5640df06d8012906b885163aa081383f9c67353c0bf6fc1da490a2ce1a1b4309d0b88c9a9424af7ecbb7ae6a94d76d00d16a8e7498331a5e24df25ac12ab7" },
                { "ko", "a43f3f979b971c9cccd3689dab029793731f0ad1fe21b35faa672ed08115c7532f256fd38c1700e89a3f35a211387fa7e21dd324e998adb2c6abce37aba50fe1" },
                { "lij", "2ce25bb875a96a20ce6ca7e98e8d3d6cb9f67324c0f4daabd4dcbaa8ade5a343336e836097a11f6da20378e0029896ed4a165d49f44ef9c90dd09bde24abbfa5" },
                { "lt", "212062798a01902e0cbe1c6e0c28e57b18eeae5215a2382dd1e5fa2cd65bfffbf01f5bb22081e0e5655e7486e954d3dc85dc2a065b6253860b8b16c643a83166" },
                { "lv", "2b03a7b495760044b5d99287788a84648f1e54a46e2e60fd07b1f6ca9a4313a6181db3a34f5ada178f5d4393796adebb6735785d0fe5027e1a16afa34a2f1a13" },
                { "mk", "875c163739c1d0c09b26ad68d784691c5d00db6235157fce454b592b5d2fa92e6a8387fbcf456df1ba6c2047216896c2977e48030004a19dac0f05e85edc24eb" },
                { "mr", "21f6df14838c66e2a3ab98068c6dace4d6206aca2c49895827d73b86485421e008be8a5c105b584c04921e5c102d8d70eda9ea29555f165493c6d2cffe06f09c" },
                { "ms", "63780a33ecf61d3038f66a0e0f661c54a895ee396a1b05a30a1a879b5a7aa35757d080c3316bb72cadd48923bde91373dd0fe8696383a6b5699416d20d866c97" },
                { "my", "0cb7e42fe1a18b91227bc4b33577194025cfff1e0adf890216493a44be504596572c15dcee10be6ef4311b99cf5eea79750a8ee11d681e073e45c042968c6116" },
                { "nb-NO", "eed2578f8c6721e23dbca1f7efdbaf2939cacbf26bb80f9b1aed7f46e33e6b1439cdc0ccfd95a6925bc5f77218c513a6630d4d512597f1c8e8b63e48e76b3cf2" },
                { "ne-NP", "69eae449bdcc1be07e1dc6407b7e98fad71d9b244abfa47f4bf94b692ced9900c9a02410eef8fc8de7f1be9c94c2fb2474f867d7c9030f9bca003da987a89956" },
                { "nl", "6b28d6f183cf87ae60071ceac53c40944983cf10b4abc56b0a27f9154ffa0f9ff893a5e690f51000678e21420453b412cab6ee8854ece98f51198b4f7fd50601" },
                { "nn-NO", "a54b334371b0c8b5e1e67c7da0d922d89340b4313bbc4a36a1334c946c40a4d8cb1b19d7930986ff088ba628a6618b0b4d6c50fb6289c118b20e0b76c3d71ad9" },
                { "oc", "3e81ce916d8af8b53aece15735256012489e648f5d26ab3d93b405d2405c11e7b7a56a55f4682fe126c62920ab21f2ee115bf165131485da125cf21f91ca0975" },
                { "pa-IN", "ef4a6cf596334d74df33584d6ebf55fd1f354680422a4311e5aa30eef158022e5a374f5fb680e6c210f0ea88874819b975ee01383fdc6e0bf399b2a15e10b30f" },
                { "pl", "705472afef6e6f130608dd2092714ca918b110561aedb3de17392c3d919a1e20bf9f5495820141906b789a3c5c6469510a1989111425212d277f7a3a16ee410e" },
                { "pt-BR", "0056c215b990f43d28bd33ebcaa001c83554fff6d2f8d0f36793ce5598d9e5ffdddf9bcd586e4422add7844c1c71f96f5a31e4ff499f567c5cd3abbdd706747d" },
                { "pt-PT", "efa9cce293f45401282d88bb6d9c345e723f47f88cfabd97376976c42806fa92b0564e96531765001dc2344f165e78121c10fcd53fb90a67d5876b566df956b4" },
                { "rm", "a0176c728f925c03eb63f22220211f50b7bb64c40ff7e656bb08155d3d876701a28f8ee4e1742b10723928610e69cde7b912873613030909061deeef39b90d67" },
                { "ro", "5d6ca8d57dcd9733446246402a63d1c57f68d649c42214ff51e3c3853395b877335ee6d0c8f5d625f667ee743a4bd195b332204dd23e66c6f9b4cdd460246864" },
                { "ru", "66ba24adda2c0f1245bae0d52954af3739f8f6ae86540a7916a2555899570924082ee5cb59bd928a475c2fabff7d9e99171c817e66655fc5668abaeb31edb064" },
                { "sco", "11cc7c65e0cc20ce2cbb7cf609bf6d4b39eedee41ae81af4969cad75dc40d6d695edc496d340906ce6a1b5b44bb3a1196c8bdbc35f37d9a7bb4d216c3947455d" },
                { "si", "c0bfadd010c9fd15e0478f80b078489572e5679c07fe10fceb4b1cf3138486ad61fd47d9526f03cbc21ea071ca64f05bda187473fd08bc313f963248333f8d3b" },
                { "sk", "ad38189d2dd3bbbe3ba6bb976de02ceede06b4d0e1b63137b62271cb4722e147ff59bb7b1ba0433362b3bbf00ed6c870ca8d0b9a0a474f402048ce245fa0c6d7" },
                { "sl", "781ec5b6222b30961f1dd5027bbc3413b3bd27df131ae6449327bc781d23a3255a4ac0322412537d875726b46c927768173b88468592e54aa8e870b19d9edc1c" },
                { "son", "6a1c029216a41484dd2ba0de36c2aa5e08f73cb0251830d742551184e55478703a9ee308f3faf9cdf09c911021359e316da5d49e7b153dbbcb7fba9fa1c8de95" },
                { "sq", "c77a9fded43d991d78c71ed5ae1b0391bd06457d3dcebc363b7d8e1d33d7a145d827b8459d1ec47e49dc319612181665124b8d5c20d966be4c0442836a8365c9" },
                { "sr", "a93f78f1e247239094218ae7e8604fe091442657b251d71a06d573a7e9e067fb7fe45513eb54ad98601877a7a10a0c176343aaf97717f34c9190f83c30308bc8" },
                { "sv-SE", "f4195e80efb835a530c92e9d825f827ff41fb8d5642c6b5aaa3fe156c3e2360c771d7e8cafd0f17ac204ac10e18f2d61d1491b7416716136556e28454e51b01e" },
                { "szl", "d2af827e564975653c332dafaa1b18119b957f2c4454b6e306b705f0733fea0f90fef7f63493c915019c2ea586fefbe2dc8ae7b1dbc734a80000c6a20d8e4062" },
                { "ta", "d504cd334f59ed1c3108f3d1a7f84b01ab23d93cc3dddbeacecc441f776851790361575ade7769cfd8e1ca4a7d11d0c712458a8a4b9c6a43bfefae0eec88fa0d" },
                { "te", "82677e2d8f4b5026a04bbfbc6cb225206fd0836047ed0906dab742175c3ac4d2ec6d70e8d8e8d23616f864aeec21de647cc1210e1a2c1ef19a850fc4d585cde2" },
                { "th", "348b89050b2113b6a3546be8cbe6cfe91f892b0f3988c278b7f72e01a980b2919476fb028e88b64102edc4a825361a59b097ce7fa8ab30550ffc631759ead5ee" },
                { "tl", "c845536e50220a0240560d0bdef4c23dee7089267ae3d83e65e79858c8efa4c1f62504055a4ebecdb119490a3b9d9665aac9075fb5c66dbbfcfa5d6846afc3ba" },
                { "tr", "eedbe8c8afa4fd2c60714f70da9970b8ef77b5355f5036ba4244696315db83b4255e7714e26ca9af9ef265bac1724d9bab4d3a8561f8fce3a4adb667933c1945" },
                { "trs", "1e63b2f75a721d47ea729e8111bcffa8dbf87d83c9db8669fb1b9d29a2b087cf3d43e9410d78b3f45034cdb3c5973ff87305ae1efdd6221b4adb3c80486c33bd" },
                { "uk", "bf2f4e0fc547d78c461e34f2f0d342af7bd2fdc558b915456033225fbb51c82789e869d2e9ea3682e96683db7d571066d28a82209bd0d4d699eedbf768f3040b" },
                { "ur", "ed10e268000e72b89502aa44d63e2edeac8bc957f5b4b3845e3ab9f64f7b4b7b8f31006752969bdfaa3945be57ed1ac8327a36d94a2568421f0a29b6f9d05c5a" },
                { "uz", "b3e01d4cbc4d17cad8252b78b61555874e012ba50297bc6bd2d887dc5b2fc764d6948ea87ae28b46df89eae8005a7a670ee96c3c35d4a023d008bb8c6918d5f7" },
                { "vi", "63341ffa6126052e677d75a6c6cc48d304b5a1ee0a4dd302353c4b83d684ef53d95cc165707923746eef001528c5e01673f742dea5438a0d3b9048a363f499a3" },
                { "xh", "4ac89d9996a8ebfb8cc971f61e10533de888a68e81f6b09a612d5a9f48d4cfb2bbd6ab894d012888838511b35d9e4b38c9fc8bf971fb802cb5240f196ac462c1" },
                { "zh-CN", "8e31ff1e7f300bf79504c004f9a7ab4ee90662d20456160fa741a231a86de7dda05b086e95df0d7cf8d1ca6379372a025558c87ddebf779900f6e7e074d97394" },
                { "zh-TW", "ec61125c4543958a99a158172552e8099675cf49a8c8429eb481bfda5be1064b4f11274268ebde0bafd76ff4043b84d9403796c67bd240978aa1b31035cae1c1" }
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
        public string determineNewestVersion()
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
