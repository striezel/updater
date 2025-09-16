﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "144.0b1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7441a00f087f6f7988e5a2b745bb5a075bff71f50efcc313ed71c856cf44bd83380a9526dcae6c66a292bf6f34379cd781008a9ef617a941f39f6c2dfb7b52bf" },
                { "af", "e8795cf24e1d601d3f2a177c949bb1240c97d7146fe0e6afdb146420bffb8c74a715f5a7500852d2d8add98c89387379cd9b1b52043e72cb01df6f60b6925764" },
                { "an", "b7210f9a653b87a96c3a003e82ff40c9c5af41681dfab69af046c8913fdc7e8309ce0f28cc9896339562b9089747e0a8d20d33995814f98b919bca9937f09bbd" },
                { "ar", "15d7823bb613e784fb89b6d1a30e83b0e4cf0db68c34352c5d613f41425f81d37541b14c84dc60e3fb054284575e6603f24b745e3ddafc738b81c0248345ef61" },
                { "ast", "db2e446be07500b84377904a951eeb3e3e9397265bfdd5599ae7ca9dae6ea73010adbd848a464ee125bc77f4b3210967f05748b671d2c5c55692952bc4adc24b" },
                { "az", "7d3d464b32e983882d5baff138e12124ec5719d352446b56fec14a9bd91ac5a8d26b1326ba9d3f414130e68bbbc2bff4060082e4a0bcfb2af90c7c0dbb361a29" },
                { "be", "9ec72cb03eea3a97d09490c5dbe48436876e1d07718c786ed34097d1dbaf75396bb09619bacc9a11dcf08a6d3336ef96b3df5c0dd224280445c6ba7d9dc1bced" },
                { "bg", "b10806c897dc6ed7599db0aab141110dd10b10bdaa6a33ac179ec75d5918242aa9bf9f7485755eea04578128f742cc40b268f127b37edae9b5e3a93a91d04a1b" },
                { "bn", "ec93276beec9a88e0af63917ce17b40db01c116fbe5875c9356e1ae8ff71c94c45e69921b7bd0b68bb36f4eb3f343686af35c3a19ad205d636f1fc77328167b5" },
                { "br", "b39ce0c58191237a9d55b7e197c218414db418cafd0be87981c5b097081ace829ec7d8800beba705d4123b8ece3b282c7f241ea4e6a5b9cca434f88c815335ed" },
                { "bs", "112d7cb9f728186f24a1d12353e9c47395e1776e79cf00b4a8d437b162e5c17af5c99d7315fd3afc9bd3c222ccc1ae3b38345f770a9b0da854d46bdc97855188" },
                { "ca", "d744fe179bf1dbbb33e83ad7251d273d86531f3e83645a46ea3df234e0b1034d00def00105afdddf0a06e9b3476ec50c53ae37eda3fbb4363a4864711e0baac3" },
                { "cak", "a114d3b2beff1f115469f204a77868dbf2b5097664c8bde1b7f3d3be3f2a7b3dac52c26a70e8c1095ad9637a5012718a054d7ac561dd117910b373c40a53b25e" },
                { "cs", "8b4e74f6f21ce7535dcb48caf5c8785001ea1950122662c25edfa76425bf224f527df84dea7440694fa8a77365b4236cff8ef4a5a0f8d6d1d0ea070c16c312fc" },
                { "cy", "e7305b8110f0edcd69493533cf176a743d5f2618bb8b61a248371364fbe799b8b3b23fcccd18a509f2da008b917ba5f6ceb0d769a74b7210dad3824a70aaee74" },
                { "da", "dbc9ef68f29fbb9733b9b7ba8afb0de90aad8d8d151dd5c150b672bc6cd942039efddb88cb75c5ed99e1898a59c1b5e3e9140630e841b5cc5f9d0b38a11d76e1" },
                { "de", "a14d7de8fc7ce48fdff4886d775cca99d7098378731fae210d48a8c39dae85bb7137fbb73f27198031fdca10c6a2813de0d27f37530cd54ec2495027906a8848" },
                { "dsb", "c812db94e48699113e8b682c5cfbf46c33399bfe6b4856fadc9742ca54c734f15c3d3a4253d55357c231ca11200fa7aca9ee8f6d62176d9ba8b583c9c3b2d3d0" },
                { "el", "4838f1502c35a64c551f81adbefaecefb78e29b0c0be4719f6060e83d2dfe6f5a187abc19e54df0860f50721b7fe54beee14b47164ae03a4fbc36fac0b6388c3" },
                { "en-CA", "10453e2e35d922fc0a5e7aa2b2f38a3110a19ed8ddb7d75162e1e8fdeec246698abaa5d74a03119d18194cab30fa676c61af368e3433a2f80abddab64df0cbb0" },
                { "en-GB", "afab82e6af5e2c496267b43a44ab3ba8098430efd5c60f6740d2700c320fb046b6b03f16b5d9379cbf76a44c29b04fd6abf5718ed9819c7141c73be720032596" },
                { "en-US", "336debf770ca08a6791d82fc91edf75d9ad4ce19e9afc67b7530812d41c54b9a83e23f64a4db49664a33a6a7932c305d50d2d4cb44b6105f9108cbd945fefc46" },
                { "eo", "434bbe8c78569ecbaf5870b6022117bcff085d5705eb7b24bade4934481a599713d0644a8efede06ab6821e0f3abe1ca4c58d6a2963b40f07695133142ee4571" },
                { "es-AR", "2d272c3c6cff8f3986adae283f0850df48559fdae0ea46271e4c30b0c582a185a6da34eb67c9bf8a572bc65914b564df3c098f3b51aa94bb2eb2f965e6cc8303" },
                { "es-CL", "577792a2b4cbc9f20cd9bb9c0d5f8caed5a8d6081847dec718576611571ed091d7639d1c858a39fbb3999ba2da4eac0d08e59adb55d9198cef698c17d7bd5404" },
                { "es-ES", "a842224c2fe9997d4fe9ba8ea7ac85eee8688281fef006e90967e8388f35d0f293993994e1d4ef8779cf7d1236d6da81e4e8930825a6ed15cec791115c7a3d09" },
                { "es-MX", "dff4d382e2bfa703b14aae0bae9f4fa2e7810f4b6d49ad510f6ffc4e1391f3b51fe15906817ee90b4c41014b8b6169420052c451fdf7d508122e5561916440c3" },
                { "et", "ac05fc9c9437c38fd29c2757d8996149dc2aaceae2ed81504b245eef22c1b5c06a680cf5ea72b569615a67f12b366b159efd33c06516f50d2d740269b2d3ca15" },
                { "eu", "2d791ed7ecc85bc040988f78ec2e124e338d2fd5c77f207e61a9deddc8f6b1071e215c6a97816b667a55a8de25a2487a7cab4dc912facada981630d2217f43cc" },
                { "fa", "ce2bc7c645f7f7998a4c249e1b9e405a60c6d84705b827d255878f4dca8e8cdb6c940a8a49d0d5c4d296a17dfc531ad62aff38f7efbec1251ec348703b400f29" },
                { "ff", "fe37d3ed70f9b44b06b2f1911193e5dfd74e0f548265bf05ab63dfce2a0a92080f6856244e8dc321dd20c24e14d4e3c59c837f36347afc02c3fc6e7533ea880b" },
                { "fi", "343efb54e04a11dc4c0ccaedfa5b748e028a2fd1a3597d95feb4a593020676955d554482bd7edfb236c19f1641141b40d1fd1ec25f1cb52817740da07399fbf9" },
                { "fr", "72414235499fbc51ad289845a425aa3db632ab0fea96c113f0a9e532eb43e201edff53ac798273f8b6af6eec83d3aca9a53729981907a24839b5dff2ea1c5b4c" },
                { "fur", "f2b1ffef7dc7b0d8d77a7bc97de429b8ff9d0f80c1543bede6a6a3db6440ff24f0171159580ae663251e8fdbf7104a8fbab89f3e7f09b62069ecf69834bbda8a" },
                { "fy-NL", "fac88b1ed1776f8c646d8c7292782055a3c6c781bf7129d73273cc5d888d75715dced189966ac5188d3f906262b40498e7fbc9e76e111b4d8f99f04b77b2e0b4" },
                { "ga-IE", "be6763850c182d65053254ece493a8cca1f679302b3cdafe81c78f36d1be7407d9dbda657f8ce3c862268d44ed5404b6be199fe86ce4777731aaf21e03facd97" },
                { "gd", "754761e3afc0e5069f8a256722d0064e1fecda21a228e8620061b41a161223cc039185910e4e473b092baa9a31bcdba224c47e8905638a130991297610722444" },
                { "gl", "6e2b96a625f217fb668bbd6945504cf23b3dc83bed60e0ad4d4089053b73f755dade8bf26717e5e4297fe1a56006febba78a50c25cb6bfd21f24bdb2619a9d59" },
                { "gn", "693ba39af18cc1417ee453b8beb733af445e3c7396c427c673e635bd4a72f7264eae92670922514b2a42a7189f0dcbe91160206a2c142332ebbba07f80b426e3" },
                { "gu-IN", "44c7a08748b19d4eae29691bfda0e7d384645ea71e1d2f745cd80f0669db86ef8bef90e152363e6b52cef81077cce5e00fc7fb3d24d2a86429218d373d8755d3" },
                { "he", "072e6a01e86ce07417444101241749a263ac41380afbe5860f12daf501b3f714b7ff423b1f3793899964a4e703e2ca27d7a759e38ef50e9aab35a8888d450532" },
                { "hi-IN", "edf65c9166d24502df855e3ae3213300f0f5e0d55eb9bf30cb6ca57c39e4969285740cfee27cf713bc5363635c8d3968af0b06b28b3b92efe83462f48eef7096" },
                { "hr", "e09ac164347cbad2f0e07c662256a032177df88ee3e5b4b11b99b7a9c70d83fe0fbd03470a46fd8fbcdb8323e47546188d9207c10365e52f2290860a2ba7c18f" },
                { "hsb", "ca72a1e3d34ed212faad7ce5fb4182e405081f2a1b7653ae58b468118756bfed7d6c3ff588a9f43b4d8d7476c393d3307304c81cd6522444679621a8fb0cf8af" },
                { "hu", "daf0fc6fa30590632aef8b5fbeb94f11631c265c288e44dede6357cb902962b50af521baa0c33a8df8a2ad0ff68f06b6e7f493aa09147a7a34d187d897a8e393" },
                { "hy-AM", "4b4917bb1337771516b73a805a81b285eba88cc72f2f950eb6f62acf4e1fbdeb64dfa04e5e9f55bf3a0bbbfd69fae5b4c62f8d18575560c62aa534ce7c309da5" },
                { "ia", "9b16054999707ebd68506c5e85b0de0f4c5e56f6cda999c085aaa41f473e27c7b982de83eabe4a177559c0a16fe870f2d07972c43b59320750cf0690bf53ab8e" },
                { "id", "3240d9db248bc019e1ccfbdcc1e431753d5a01d0283545fb6e98b258df582130b2f97716f64e61c013fdec0715f05f0669a982347af25a1c8b88bf71daa869b3" },
                { "is", "315eb6cfd26859a4ef1d49735cfcc177834123db35c307cdb96511b1cc6dc4c8d03db4b6cebf6e0048b5f15281014487bbc7da3f143d230cff1bf4eb9813ab7c" },
                { "it", "0c622ee33ca02466f421e4bb506ca70d2ad70abe0b876c065f99f595eee590a44339c3c4df691ff39830a6b0dc59f0e0dc02fcb49c68146dea014286d9b6cd36" },
                { "ja", "5447bf8196bce83e11451a039a4cd8cc28691f2c6e7ebb7c0fe328a524282c230e084d60bb6196049fb0350fc74aaeb49d0feca6528b4c81b373b9281bbbb570" },
                { "ka", "4a0fdb7bd104e0739e396f725c6d73c1ff42b569554b616d2398a29e1b8e7a80d57d89baa86a889f1585d17175789c5ff792ce534a438cdc08141c43abc7e355" },
                { "kab", "78e741fda6c1b5a7609023dc9d5d14fa9041b13ab947a841574080fe66e521e6fc9aa0b66f5044863783c362bf33af1c2ab7e9e9bc863906e24409edf5b3093e" },
                { "kk", "fec4772b1d61a47b7f25cabb00dbf7f305ac0cc6f8a1466d3126f28b87cd4af64c2cf16b8f23712363eacc12e7936ff6825d39409416857efb114b599ad1cab2" },
                { "km", "1827719fa9a5581d28c50411a6909e73a75742c1949fd010fe47774ea6c0503442ef5456d9c62746fd22420763dcd949500630c361a6ec6d7a57a2f9d67dec95" },
                { "kn", "b79a944f4a002deefe06504ce65867aaed705f8df22fa9c06864c80c3ee95d3e12b65f2c0bb64eba9291995e326255b3990bd10fca0a0faff9125ceca3d25cb7" },
                { "ko", "31502ed03275e0f507e63a7885479a1d5d63834af1415b946225ade71302a015310082c81f6fd3e313b9cab1036ff7b621b4751615c194abc3a234113622fe31" },
                { "lij", "4e28f91988407fe9f27eb7726ccf828984d8eb8c1a268391db39fcd121743a68f49853ec0ab2cc17723d95f5915ed2fa81c5333259dd767de4493c46a96a5f73" },
                { "lt", "00bd8545bbd42e7a321833ba2110940ecb83e6c65b23305ee7a0755c55768f89d93202395e617da03314416866147f4202f17ca7ab7d3232396dd71dc4352dc8" },
                { "lv", "53d53be9e42712d8a231b988aac4e146dbec921ca48e76a3e4d441099d4ed40d57d30dd7a0025540a60a73ee27dc74137f46b89beae5378ccf84fcc683417363" },
                { "mk", "99e75d672ab360a2b05afe35f0087c3b48f29c5a6d8549d24e3bec3294feb3fb7140b87aa9cd5f964548d8345c1bb78bf5a97f606ca3378e230ba2845f68d0aa" },
                { "mr", "daed43d716f187e52aac397a7b04025747ad27c1697eb2dd68e9c9b2da4f4ccbad236660aecd692559331e3c33b685371e9698412d7a1c21d0f5cfb414d455d9" },
                { "ms", "d1fbb370cef11c92e0d11d1b0b86db9cf7d709f39734f859eb3c01a8687a31d7ab8ef158744cca6924bead63684009a70c741b24fd1fb0f3dc165c3d8f4af9af" },
                { "my", "ecd19d1bf032ec6a917a9e0849920578e5c5ad84d24ead68cca8f13919fbc85198f78d709f28f1a009c1756e5ad42b6ee3f78444ed1251cf98a454b8167d6ddf" },
                { "nb-NO", "493665ddcd4f9d9af4a8171e85e78a133e5cc566def9d7816bbd2252000239f8842e5aaa4fc7d3176c77dc75aec2962b29d3c9897155812f5a8a22972f28613a" },
                { "ne-NP", "0e19df0e286aa1d9ab003ab31ce79c59eb82850feee4ad17de46fc218e15ea840bf19641e95455f1c3fa96d8f442e5c41d5fcd91dd882d686e0f2a245db6e6ac" },
                { "nl", "064d232196c0e72ca1cd95219055531521640d153ff56dcdf2076d4ae6856a5d37de6ce33c87252ffe120a322df5141f1e72a9d0767003fb89620a58ad45846c" },
                { "nn-NO", "eb8309bf48a970d6574e08c8bf6432a6d8fc2124839b4fd90b2471414e30eec924f39f01420fdb1ff8f0f61f212133da18fbde9cc91acad900207fde35a3d788" },
                { "oc", "a7241655596936d4a9ccdffadf2ff19e16a1730737dac232a4fdde41ffc2966f4cacfe8ee488ac0823ac9137ab954d511a71dbc4f9a1c0934c7a5b3616f05983" },
                { "pa-IN", "8c62a2235a9fbdc5abd7fb3d166e9e80865d55d96adf318e9427872f4bade84999c7bea8b993f16507628487992e714fcaa8cc7c605ae39e769768e42a62a243" },
                { "pl", "06ef6b1259369255d52a95e8fd4137ff56eae7cb55ff2168b3970623b9eeccda5c43a656664e7ce16ab9b3b46e02b9203dc6a834d7b77b591f5fe60a4423c629" },
                { "pt-BR", "5a782c8f5f904afe7c1b605324a716d752bfec87e6e8559edffdc1875e322a20fc377c4e68edbaae8e9b6c1e79521e008a5dac7d74fa8559b3ee192ccd4786e2" },
                { "pt-PT", "6c22537dfc2300282405fadb8c9bf9adf7ef4791611c46148614bdd2eafd526f1e81858188e41108da2ac55dd2bb29d54b876bd4c614ea42223a1a87d861faf5" },
                { "rm", "71a754f501cd2b90e010c28b2fc73b3feb9d2b868466151aac02f84b7a16257d34f09ec47b30f4c5987246b3713e296a6fee4748ed16050256fc993246c5197c" },
                { "ro", "ed0658bf9360903d723aab35b57da744d32633e68451b87d33ba5a98d0427a3377a6514b1e5db0ab7179974912bd591b36444a745e04219d84a481ea5c577875" },
                { "ru", "406188f026d12376b4e10b5f0c2665ee8c8d41a5c0275729a17ad96a32dfb824363f4d56e74632c681cae392b922f02e8c5d6f21e63cb32e0ce1c717dffefe02" },
                { "sat", "57c4acce0768c073bee6779a56dbbec96fd4142bafdb55c93959079fc0e496249875b5736bd05b652c30d6e6adb36d5252983902f464753b621fd04a1e08c71d" },
                { "sc", "c087894f560e730db76db7de7495dfea012e94811cc26181e6e7bc2e21cdf6e6161f5f8c6947a4f5aa5c89c93ba1e6abc97c47d2ab05747a03f50519c3851bbf" },
                { "sco", "86ea4e683c7484ad66f4d0d75151ddea4a454a864acc924f4378cdea3d97f511910e320a339d1ed05bd397e4fe8d1f718fd86a2f8ed19c86a85b22f41ab0fee3" },
                { "si", "48d4e6ca80f3182c7aeb44c58fe8aae11d3a9a414f9892e7e60d0b48969cfbcff1c4362e368b275c70bbea5cbf7afdbc0482035d3f2de2cba09757cabc9c424e" },
                { "sk", "022055e98af00e76002e481591ceacd33dcd695d838daad3b5215ce37738949adacabdf4d4801829eda20d78d72a7f3a4617bfa0ea769e710476bb444b7cc4c0" },
                { "skr", "bc7efad7db357595e3b9fed29e0ecaca11cb15c85db796259269195d5278123c1f8292a63839d3cea1cd3b00b8165049ff1db4c789614512cd02cf398ba6a2fc" },
                { "sl", "d1b813d2d9ca303b17a9aab2f52f15f1b0d05e7eaa95819f6f5d5773f3d8c74cea6db324557edcaaf0cdd3426d29f8430bc7fcc3a50ac74766ddaaf69093d299" },
                { "son", "518809b1b2045e284d0285b55876f586a63d77c824878f1abfbe45571c148274abb9c2fa235b4b8f6ce2141e308b5c6537f6c433106b90426836d5a0e44276bc" },
                { "sq", "0d614df85c17256b450080b0af624504bbd89d963cde7fb7e51e71932abd4a118eefd9455a7a2347edfd1bb23757804496afaacffac371ff1ec729223fd23352" },
                { "sr", "1ac2c651a0e04049db5517c1eeb9a2203a4603df4627211a8755969f8c3016d42b1075fbf57ebaac515befc0bdc6dbb82c3d73794d72da05883ecaeef3911e31" },
                { "sv-SE", "b347f3c70362137935385091452bbaca0ce0e0565874c45a5b2d9e79a44abe94037fef0980f8e564ea228ea2530dc6b288ef7e869809f536ffb3730bafa63f1e" },
                { "szl", "51f27c6ba423f10c2143dd846662ea20411399f36cbcfe29e2d872f4a97f515e75e3047089c555458a97f1474a5f29cc228e5a7c34e9299f45b59208b52b0cf8" },
                { "ta", "330fb901c6806cd89d1a9b428906b2e424748400f9786721f2512f45a223de48e83bd67540a8eb059752f49e46254d9e9476f2e750b902737010e39e87344007" },
                { "te", "257c2922e928477b2971ebf7d6f592f60dc7bb173c974fcd4fd7401ec0ca204a2017f1b517dc8e12a594d26ee8a8ec4897ea6fb606c3cb05a2e63100a71c03d0" },
                { "tg", "344646608b3c4904d2ac633de7a7ac2702bef42eba16f97dc57b99b1e4cf5e881db5a6ba0aa75666127e9536766f966b4b01ee5b23c09a5645ee1a3db4dc9089" },
                { "th", "418a7162bb23b596a9eea89244abedde4df1456fa6047b0cfb3513040a0b8079be042b50ffe32cb6bed238df9999b80290a7e3b549150748352060be241bdf77" },
                { "tl", "b77539365d2c9c0d33b8afaa21c6c0325f0a6868fc818f32d629348f3a9a7fff90f67b85b9b3ce84ed88920503216a5d0279caee10489ae83bd35cd7620ed13e" },
                { "tr", "cdb94280f24ecd9ba3b7f8575b8db9293b0fa7cca849fff89d8a95229895dcdc8200de8aa042ecad12c3de756584a60028eb20492ea687a636bec9a1f795e694" },
                { "trs", "0a6ad37a1d63b5aee6a9bf381f4a10dca477b263b9beec81f36e1978a10517ec2d043ae78578517911fb404cbe0fae2c8622318dc95c93b702931bce1cccb413" },
                { "uk", "75885d1348e7e073f18ee9103ec16a764ee9d7dc58b085e7df05b02c525c14a4facba89ba031e92d5f0ca966a1bb41457a1dc27c21b64effa045b980bebf333d" },
                { "ur", "18909f313b659ab8d1857701d4efa651991db5d7267517d7ce01761e98539dec4829df8adbd74611809735f8ee8bb99d812ff8684cfc3cff366f6456e1e0bfd1" },
                { "uz", "fe00ef01ad5b7feaa2860afe6afc01d5e7e2036e41ace4a04a71f886fdb5796e13900da7d58a2afba176445642ddc61afa8920f966dc9a8aa00e9e36a8accff4" },
                { "vi", "9a829ba8be7d915606ad6781b5be5ab4d3b2fe677978d90b8dc33c14f16ab19bb347af6e05a2322eaf53dd9d3368af183a7b2726ad1b4ddd93143fe2b1e45f06" },
                { "xh", "e28fe8167435fac43a31df1af805171795ef1423c16411dd6752d4f730ac6dcba696f60f211c1b6e00db0d3dbb77c42b511ee0f1d182af51d65cad8d11a83b5a" },
                { "zh-CN", "13f13c183f983260436f3993d28a5cdc9dc4f1b53d144073d0643ebea050e52e59124ec9949918f4533d1f7d17d40a4201087a117e69bec5a0b79324f992e4d3" },
                { "zh-TW", "09a8931306870377a7cddd7e11964b90a1a8e95f8f046be4da6bfcaece63714190ad6f1108fe621044e91d64d6aaf00e13293486539e2b8a952c73c226707577" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "111f4dcbbc5be3c6f9a0ee2f26b07b2c2f6081aa9bf252ce0d7c971d3f86e327b1c266bdf2779cc90ff2a53df99bef5c9f7b137c090cb1ed1598a08f05c25525" },
                { "af", "b1ebff45d38fb35e264f302b79b599076c18577292877e51a790070b474458bd341a747f20f24c8b447e6d1b58e47bc9818124264287ac88eb78479f8837c4e5" },
                { "an", "276296e2b560032b7550032a7c443431cbf9bee2735636336dcc3a376154f1441a8db08d30cfefd23a6547b11d8446f781ef73e97e9b975e5f898916f3523c19" },
                { "ar", "6c438f728061373d3b0e3d8cd88e149a2ab28a0548eb42c4588ced2f5227cb6569c2d5f54870af98bae7bd46d02807012cbef5f6d188fb6cb2774bc76b09d334" },
                { "ast", "fe3a628fb53510924a26b1310500030ebeb2a87b3bdf50e07ffba467a7af18fda8a91f241b5f1d0b2670882bb7e165c71fa56d57cb378467bfd0786aaa021675" },
                { "az", "9f63816b592c407c3b86a6895f28202b412a51af5f11716eaf6fa64756101dfe5b3384429cf6c6f91fb41beb97eeaf85bc425b1360ba41497dcfcf47bf7725b4" },
                { "be", "cb4b7963bc85ea226b902ba6a4824cc5a127e8e055aa0d36e8d43b19566e3674e59a707e6be915b906d780329d9d063fb8cb9d421c6362552bc0ffe916dcdb2c" },
                { "bg", "f28be638290354ffc591c2a90531c62eced0a7132057da7e4d9198c277c0cb2cad7dd24cf53632b7acd989030bf179635c3eaa1f8e25462255b9dd1bfb4dbe65" },
                { "bn", "1cf3e1f73e3af2486ea82bc9b23bdf07bf1e0b0a1642ed1c758ae668dc6be7caab5a29f9a6211460fec1b8fa8f3aa55ec59682f97a8b207251dbc5d1be34cae2" },
                { "br", "c64d09b83f46d9f8c515febccce0ad49e43753737954b878a84f4057f2c6fd54bdf25a7d823dccc121bf6f516148dde56741d66b93310eae4a5aa5bcb75cca71" },
                { "bs", "50e75a6a183391d4b7356f0210c94557773f33318ea4f3ef8c8ec0a39ca28e04cbcee520c50c4f17c4b15f75885b8b888a9232214a88ae2130e86590489061c5" },
                { "ca", "da4256b6aeb43270fd786a95666b502541dde23646fd5c5e43f5688d98a0c2dacb7671edaba2d20b8a11003ad96dfb754c24cd2d3ffb0d7d4ae1f9a5e6f1646f" },
                { "cak", "e1861f0c9d2c4db698cd2652fa9564abf8058696cc1f017b1c1f13695f1300e50724c5e7520be3fb7572b0708630f4e30b09ddba496211c40a4452c869bc0305" },
                { "cs", "b298648c730483aa99a61cefbf404cf8b9ed62d514e434ef9fa56ec95448d23b46edf33d96546c92c01789e183130aebbe2ff01b2e0d44980db02b622e862d58" },
                { "cy", "ff01b5b574b50191415ef76af97899cf0bc3e2c907fbeda6691c2c8009becfd2babea705f1f9f8144343d4410e1c201d18f24dc2383563abe77d0e008b981bbf" },
                { "da", "34f30a37ec9c8c83126b357caf41dd11758674184a9b043dcded995838d53d1e97c1e6ec1c420b70ba8343518eee71283b95812f12af2b9044c4630827ae5b6d" },
                { "de", "7c6dd88cd420a32d22dfc35c511583b2538679ce99eb32b003af530746bc57e9a7bdfeaa83b0e68e3c2c0c4193be3a2c2f44ad2ea3352f6dd63313d9e7d4d740" },
                { "dsb", "8f0a958af3945b1d8e8de020708b03903fd2fca72b0062c21349fb7f26d25a0e4987bf464839bbc291506c1a740eaaf8336652461e3c50da3b60ef8beb71fbe5" },
                { "el", "f4eadfbcfb4d9e6789418cccd9c40fc1aaddf7fe33c7e44f87b16ebba667f362c49ecd2d295664eccc09c6c9b4d3d1f59dca923384d5ff1cbba5dc6c90c4ce5a" },
                { "en-CA", "68d48d29d37acccc1da7a64b8b9219391a2755ef01dda7a7c54764afb8f5821c4c42c063f356a0a04d57c19f9ae74613ff765c510cd6b18a9fa1066f35c142ce" },
                { "en-GB", "ee5a64818cd05be392907d7f53798b3ae76ea316e908bc862e3753e9c42f23a087260278b3fef4a311485ef5a6826bc8dbf5cae5bde3db6c28d96e864d009738" },
                { "en-US", "de09b59f3b431cf6c99e6169d93a6176c17a903adba7a965fc9140dc3fef6181a1a3fa386f20c397e27d0252f17aaf9e19a97bcf828e1335d686f3fca770f7c9" },
                { "eo", "1856f0c3307ec734d66a06f629b62f169a65c8038d1159ad3b7c9b29f86236dcb0b4d50a7eb05a5aade78295ad5c8dfcd4858556a9ed96a7425f65fcbe4993e6" },
                { "es-AR", "b5c378f2e866d08811986ef404496d1db418856cd08b26dacd475f70443dbc8f3fb343b95c3ec5533cea3067f381d02880297fa68a020ecf6940aee055aea70b" },
                { "es-CL", "3817b2f73cb71443aa68ac12945caf9d8577a8d2ed636ece3c8d459e009420bf4da08e16ac515b0bb5a0d359c91c1d7e355ebef31de50198dc66570e3eb4994c" },
                { "es-ES", "64e24f1162a08633d7922434a325accc04eed6ab175b53dfc4e9221d2e33270eeff9d149e51866b3c9d99c2fa13196dc39324a2bd2faaedbde3ff8ce15bb9719" },
                { "es-MX", "92f6598abc24eb7fc6b825fcb4be039bef82328fde35037c4b9fa6d9754f96070402952aec91b9e3046162e4c7d962ac9d3be92892e1a99ca81797d8ed8c0d10" },
                { "et", "809e1cf95a022074b93de46c452c59793554703b170b0395f5a838f5847433cc5d82ae070dd08bc59b55c004c6c15b3d4378f0d07be5c70976932bc20ecc1d78" },
                { "eu", "196ad96b0091e76fd538c6bd902cf534663fb41eebe1cfb87e95b5508a1212a578fdf3343b69b9f796bce1d030a747c188937569e51b51cc1933e15f68f6f411" },
                { "fa", "6afea89b50094aae7c360bf21d0a06015befc22f47293bde5cdcafbfe5b2cd697a723be1594ae312dfdf36c764f7d097a3ccba8d37647cb701215eb869fa2d4d" },
                { "ff", "0a08e2cd364547207f97a36d010cf16555045acf899180bca1efe80dcd170ce0cb3d899ad070c55282b27eb7f144af3a4b56e582f420f58051ee65a3bb2dcc39" },
                { "fi", "78d251cb90f219e0bbf7f3dd75c3c2fa7febf3bd90a557a836488c40f144263d6b3b13f49ba66bc0a7e54a12591bf3dc15ec77f96125def47c0f77384b6d06b2" },
                { "fr", "29ef79632d867e000b195c75c18dc0179c3d1978ae9bbe2e0a7825a00efb1da144a5f24a5ff4fb79eb0676a660611885cfa0379faeea9b263996625a76f0399b" },
                { "fur", "399d99c79ea9f2b7f78582a94533d40ef0993812ab8f6ea1852a1bab0f5a0af80a349a58a95ad14135af9dd01e2d9e120a79592a8b96c8f1cbc91b750884a96a" },
                { "fy-NL", "2a486bd13057bbd5852224811ff26cd3ae1459c8759db717776987d5dbc8c8fc88d65b996027174795ef1fd2419d4125bf6fc0f59ace7ca7c521514adb5c8d41" },
                { "ga-IE", "567e5d7911ca9aacbb6af8f2039dca04de52c09b83c58de71319652e72c02673012e5f24d53d1a1177a0523e432d8e70a4ed5c674481fd5fc048c9ac45e1a32b" },
                { "gd", "f88a90a837a53690878dea47490ff19dd3fe00862b6bfb5601b901920ebd6d0010f93ee273a0ea27090f21d6d7e253aa88c51d200fdd5b9e1d6c373843efc905" },
                { "gl", "3f36ef92a7c7db73679dcb96c2c0129773fc87bd08a00892881dab8de050ec39b008d46eb4fd9494d8f62846d119bb9e197d3cd72c6c161e092052a332551a88" },
                { "gn", "02f252ffbdd3169308ac5106e48fe1f6b931de0f3e6e2be88d7ca8f15b19e1bfb53d9d766f74e7e67212bb951971cef1521f4ef4f76303031ed16d5702e86045" },
                { "gu-IN", "325aaef3790816ce175b3b781eb7a53261a2c9bacd5fedd338c5e5d032098b0290a3fa6fa3e0eb1f9cd8ed50bb9d9f3364bf00366e5a41c1b5c5ca2a477c105e" },
                { "he", "c1cae7e29435aa4a003d8f917b68a65819d80375df9d7f26839d02c4d3622863baa06377d0d711a8ab263d2da5fe1dba6a10dd3505ce87f1d3e7e9e15ff65b42" },
                { "hi-IN", "ce6aa3562e78b67512bd5896550df958e8829d9a23647973fcf2b15b1a0a6e9030c53bc19202dc412687649e97094c9fbb38e6a5cb69bddf1528349e86903797" },
                { "hr", "9d4fddd9c4e44a70f8c9fbf3bae2f78bb9e62e77cf7bdaf654fb0e5fde3467afb736c3323829eba3d0fee1b90cc187de5d21844fa3f64b341fce188139c3140b" },
                { "hsb", "8aaeff8505fb8e33af8b6896d80d324286fb034e6d10a50c8f8502ff3e508eafba783b0c395bf79ef66f38549e7fd9d94212e2acd8348814a455cea804236224" },
                { "hu", "96d5df93486588c9c672173ac3c009be1a4c507578fee2f71ecc26a262ba02328972e26be624a3f76e51530274dec579604e07dd97e4fb147e42137f82aeb102" },
                { "hy-AM", "880dc3d0041ece85d0ddbe71152234dc687a4f3f3a24d21ccba7676a83d32d03642d0adf7896bc2f66fb3e466a893c697a07288b3971ee9f3db1471b140a3396" },
                { "ia", "6936ef2915ee281b3d248b5c01afe78c3c8472c9cfe09c9c1f136c4fd6afd1bc7f7f72c03ccf58baa9eb93f8ac13ab2bfbfffca54a4fbe4af43d9176bf6dbca5" },
                { "id", "859270ffa860f3008cfd677426b72e986cdc1747eda7d668fd4f27851a6888bef3154201a575339695c49615fb3362f6b6da6faffd7b321b38afb9ff370680a5" },
                { "is", "f62ffd32c3fdfd85f145d89ec04cb81cb0ab00150b98b5f66a36c0f06e72927821782cae6faf4ac36b219f07d5bb8c89f1927e83da1504d4938ff16939e843bc" },
                { "it", "eda16a458c9f75ab980e8dc244f17db1c979410d1766e588f3903882c50cc731a820671bb986b263e8ac30e612954d2c49b731def7ba49bb3edd4826396d0c57" },
                { "ja", "716c10aeec604479fd08ae174919fb061683df553c2a02187048fd6098631e6fa1346c3ae592dd0364b442597fdc9140b117d11acb766a488aa661e166505f79" },
                { "ka", "3e332f7e7eb51f7a3a7aec7ecbd520d57e8c2685af7ee5d98349c8969e89abdd9ad130b0156184134bec02f6bb7008a7086a46d24330dc7b7b270bdf5c50b481" },
                { "kab", "64416c2b3a0e5f31be721c22f338d2459e4762eec2264f8fa8cee3aa8b71872c88b3e191ffa7567e905e0ec002e75520d7700c7a207883dde7136a020188f6e3" },
                { "kk", "7f4ff964c622859fd49fd0c0bfb0b0c3f012d1d311aeb22514cce0d8fb142bb4ed42d87ca1475fa7e51a668633b349b6c9fec8f588eb0e7ad550264c92fccc26" },
                { "km", "9760ba69798e1718b7eeef6830e06e05dcdd59746e250d7b9553d496c634dd0d4a8da689247e736267eee5415f4ea3e8020caf4c2a390654108ec81798be04dc" },
                { "kn", "f1aecc38909fafb510bb7a7720e60441095d4188046cd283013deb58bfd9c096d1c2cd22522ecbea811918ceaf33de7e48aff82f42226ab6fc69795402c68684" },
                { "ko", "19cd6d4348615b9101b7dcb1ccd39ea58f2ec9184a1f481281b07223e5316eeb93164baa590aa1c01d20341c451646b7f4bff8b757c898af00871a250d7ef6c3" },
                { "lij", "8c169afad6c6a6c6de38198e14479c1a9e768c4da2b78b7957a789f676a0e09196067337dd86038d95cfd808b609af5d63d4bd1f5740511cf870ac33efd3bd94" },
                { "lt", "c4375afc3216b563cd02be7fea5335c858adf9e50b4e965e91ec76069cb4a97ceb18fdf16a8055d9bb915be0d28e892c438d02382848a5be14333ac80385b320" },
                { "lv", "c82362953e5288ad07294cdac0745edb203d95338da9ed8e298614a43a6fe80760207d14bffb53aeb0e49ee7f66b36ad6268e518489e865dce81165965a34d75" },
                { "mk", "ed9c1acf9bf3bc275c1ba1959c8e640aa5308811e624ac324d96d48494b06a71fa0e9359441923cb7307a9cfad76d5f72dd2d45f2668c03341fcb39c1a7cc79b" },
                { "mr", "ae7f99d3a9b0adb3fab16a4c6212be5c1694049c0a98e16a2bcf026b2b73843a2fffbfa7548faa1580b2544719bcf89f47ccc920c8deab3de1d6c50f99bab75c" },
                { "ms", "aef9b959d9e7f8efd4c0e97824c0bcc798cff4e7164ab5bede3422087409e14e520209a8fd28c9a612968aa531e1cc90de907adc9880baf33233c2ff549f0ef8" },
                { "my", "d4c207212430cf89cbf5545971c678b0cbbfc2d19c57b81d7f0c693783b6f536f8790e2eeab603487e2abbaf0ccda3e4a231e75ca0e1e3bda363b0f461abf6eb" },
                { "nb-NO", "b74d5771d25a581ad46aa5e39975c02af794a5adf51061377ef2f14f352d8fa5b021acb84a05eab78860376a978fee21ada4eb407b29071b7e3ed6101a844da9" },
                { "ne-NP", "a51b9399f2146958f2b57ecb353867b0bb4471e9b57edb052f4147db6293d5b99d3cebf6d7cb2b264bd1208fe88fd4e6d2fd1a48a16dcc2e4c2a14fc8902c69f" },
                { "nl", "78e9b5e8dd49aa27f716405f9d1c871af21bc4b867ff394a1823f22def7fee34257c664afc07edca9200a8c8af0965941f596672f1f4b57072d8952420de6d92" },
                { "nn-NO", "2e6dc5770d5e21bce858ea0f642319aa3a008ffbfdee3477adfee261bd8ac4d46df3b8f83f5cbaf8ee4cf62d7b31e86e39fcd4ac09393f8ebe048b0d7b8c3e0f" },
                { "oc", "ca2094785a793f8e34bab1485b701adcce1741e30a64f576c18ae252562e4cfe2ec12067ff6a86cfaa80ffdd97cf2dbbaf5f6de24b54866ba89d8e611bdae8e1" },
                { "pa-IN", "1801e923445ff947522d1a57d62ea123967bf3ee9ac4eb41c79a52eba2a399ba65eb0ae40db50011a43a15764da0b5ee38f1926da9b9c39c03272a9abe14c56b" },
                { "pl", "c15ed26b62866a5c08c4bb325b5991a84d91f3b368f2791517713f751ea0ec70b48ff34e3e7ca935d9850ff95cab4bf5d95c11a9b8a83b4c625fc4670e80a595" },
                { "pt-BR", "3e972fe96e4f976e835ae4272896e0a40683b3de5dcd7bbc5f1412c063369376bfdc0f1cc6f277d66fa026d48903afc786fee3c891f9b2eb32c88e925bfa38de" },
                { "pt-PT", "59190fa6fe101cdfca321edff8f1d8c102aea892dcc23486a66ff93ad13cabb7bff616be2ea871f113cace2a7ed7e4145ba4f5cb0ccd946c5ae8dd0edf044670" },
                { "rm", "5bb1fa2642cbf88642c6afee1ee99ec73181bb8a5b3d105e928266e1145bfe70261b709a4295cdc963870fcb0b2c147d6e0b0c63ce7be59912708829f48674c7" },
                { "ro", "de10c4d8adfc4aa4039310db13868bbbdfc078edb8d85b8b355216e21aebe3e7e9efdc6c4a57234463a36552f20e3e319240cb8fb7e82caad0d058a36437f48f" },
                { "ru", "782d4ebb5af77ab106934b7cb6f19c19b3b8207a829f90af875264da682305108bff2802a13b0c42e6197301ac0269a2dc9c65221b3d6a2aadf5fbc3f363fccc" },
                { "sat", "255050e7b41620c22f7af3f3152e1f17312a5e8a187b2bce63491e76caf0cbbaab53c706fada7dbe1204cf5ffa4b7bef03b343f1e980316b8e3c315e21c79a0e" },
                { "sc", "14082fe1db0e509dd91466fcdba78a376742972bc90204a70ef7af8907ce59232756246b5d2b28ca864ace0929ff60c2dcd379d73c8dad0d1e3bdb30fb4e3535" },
                { "sco", "72a041dd2954d2e9f31c8b7a5da82c7db14b844b2358762ec9b49a37e0e44626f88d4b8a89d26e7cad7e9238616d127c6b11f4c2748c621478826bdf1b5b4551" },
                { "si", "65e37c2de0331d13cbd99758ab3a6f94b1625deab14ec807919a6ca45e1ebd1dc455bc1ee803ce255b236d445370b2fe35294dc69d2062fef77d49078c9b61f7" },
                { "sk", "03e772c9d660f7ad81f26b84c5ddea93fa05ca22c90b4ea4c4a2db481f8f23622fc428b2d6feee314871e18c45251eebb88919276580ec60511b77a60b2a080d" },
                { "skr", "2dc5dbf2b45f375c64374574d636ac140592d197c42dac253ab4abe7b871c6eb5e6e8a6f8a843dce2fd9d444f29345f3eb546f93c3934d38537eff8a3e3e3b04" },
                { "sl", "dff0040ddf6c6d6f8106a43e72c52de9d37ab063399406384ee176d5ba114182abac443d1f04161f21465d24d6a6a5087c558e63f6d4460ae224c7d929410e8e" },
                { "son", "f091832c3728ab2f1ab1027c113b51150b183b5ae1a2b1f18be0e74f6c91feee0b2fc57da7f454b1b6c12dd1321b49757997e518ba362ca598df31c995cc001f" },
                { "sq", "057e66e2b94657e95ca7f610f382adf037aa67ca12e94bd6701c0267d2d105fa53f3a54e49d389413758fc3e30eee723b6bc2241963b5a7162b83cb4999f20ac" },
                { "sr", "4c08bf76230554d9e2f51b6b75ac9f1780c825a07bb6001313f0d07398c225124f691f032dfc18fa78b8044c3fc6a203af8177dc8ab6695e7efec5424f1aa025" },
                { "sv-SE", "1654818f25bdc0538af41cc330ea507215410611e03434ef559c196b8ebe601afe7378c1dc3c2afe7a7138ec5567d9ede83363f8b751203ebd95e428435e3545" },
                { "szl", "d561bdebeadbc2da461d6cb0d546ae08e2e66a961c5ce8bf05ca4d177d708ff9aba26e83bff6bae0da46d57120cffbc82800ee4411616e198fe903b1121bde12" },
                { "ta", "3d45c2beccc77a479cab2cb714f480d5776920926bf545950604e0aef638d6bcf43dfaa2a6b90c560c02205a18a3df3d7a3e018288cc6c2c599b3756a26839db" },
                { "te", "7183b1fc26ad3017e9f40bd922652689b251c4236d66980d7f8c37d0f4f495f26ab2471f39d715ba962c5d74a2658600b1d4249392d7d6f1b1c906b5a127bdce" },
                { "tg", "2da6df363cb4911426e4d1833d5b733b197787e6138e6f8d115ea53f827b9656626c0043d8eec1d1c767601fdfccacc9b5d4700bbd69e909865219f002b41a62" },
                { "th", "f20fb35b2b03b6c1a285e6171b77bbea40095d584f376efe15c247d8a36305d684682a4cd55f703a8fac081e97aff5507b9a9e4846daccab1083ba23bee023e1" },
                { "tl", "dc9670a04c27e18720f2f4ce36d1f2cc0b0f76e1a0d11a2f5fb6930cdb2a7ea78d19e1f833d6d99e9748cc6b0b28397a9d4be12239a1b9d9ab8c3577075f670e" },
                { "tr", "8070e9b5cff470c3f7f8ca1681ab35af756177be62511017105128404ddf1e1d1e07220010059e28d93d2b250a4b10396eeeee062aa5a737ad8ee0c830ddcd4c" },
                { "trs", "30b5a23b71f1061b4d27681ec8a796466bd05695badb4bd01baa5662f32735271095fa7538aa88496f1ba9e0f67a49f3724eefb8dfffe3f1aa44903c8b58959a" },
                { "uk", "1bf84c45911531bfee5ef08ac226c23eb5af98f07ee67a3c2da9efb304a3071de90dc3a6e777aabc7ff99def84bc6aa379ee3bf3a41618088b1c4a2d39f0c042" },
                { "ur", "36d1a090dcd75fe36f8709e1e2702aa2853e89b387a62ae07868db4ba4a029ba470d43a445e2a004e42e45af7273a3e75b8b342a79f44110c6f0ae8c18ddb3cb" },
                { "uz", "6b8bfdc85bb19485314c4ea5b591b493904e06a052d93e5f29db9a0776dabb7a04c42893815ae986bccfeb7cd9adeaec3d43a4b0815de44ae745132c279497f7" },
                { "vi", "8584689d09b2570fac2759d98876b2578fc8f4136fcd44e00f80fab090339a033234f997c986c956800fa6e372ca5a5236b64593a72dd1ca2d6c31714a8b9958" },
                { "xh", "62f8d348eac58c7e5172ef2ea5413dacb567f3d66449540640f3c2691663599ae85fa712bea953ee80350393b61245d263b637da54cd21ee809b621fec5a7efc" },
                { "zh-CN", "7a2cac26a8a4f9c3be3effd03b7e5bbf13d76b2e56c653d1993a354e5fa9e5353bdcfd82a58aca915297f399bdf344bac0d24cc48bb095ceff24a9339a863b54" },
                { "zh-TW", "64882231ac0b55ddbe409503cf07a725a6ff0ed29ad7d8d172da1c58028ae3626f9dd23eecaf2657dc6f44d353d30e95037b8f4d176c58c03ada1553148e55f1" }
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
