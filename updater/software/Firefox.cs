﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net.Http;
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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/143.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2fab16300d06673ea18d466e1fffa8d316056d94d35f7750542c1ccf09a8f78225ca6f576b0c3097a827e129dcfb5094d2a2346c547aaac06c27eeaed7d794e7" },
                { "af", "b84a7b46ba2b92de18b82249fdfb3e315d2235e4bd2cd5cfb5f38c5bd189217e61b41b8dbe503f51bea5bb7afc7437e386a4d4de52a0714a23b833df5117e141" },
                { "an", "92c6451d6b0a02e8458e8b4876a8df3390120f99dd678169fa0024909ed867e88cdc2653590c0d1c1d36ab1e7204b16e72fc2df0947154eb646b7492c330476d" },
                { "ar", "6e51b313937937612156aa72f80cf1332f05b3ecd7be4ce0f423d20b7c49adae438b3314ccd9590f4153a61731e8b6fe04d96dbf99efcaf9e98d84e301f31da8" },
                { "ast", "1261aacf3c76a0804625938b49fe0304ae73343dd5491ded1dac1591bd2e10d72ab1c8421447bb4e89c35cc11ea13573b8ca38bd95f914abf86b035829c7bc09" },
                { "az", "5737b19b5f7d61b9e362c4ec52b364ed8c8ae676d3c704fbb8fab1e9e3f41bf984090ebf1cc1cfe619eb98b077d6c2610df05d0e9712ed7a5ff32784803b537e" },
                { "be", "913f4c19bb7f900ebcf8acf270475f2f7e3e9f6db07fe5ef6e6692ace5273850664857da2a2ce53c0daa6e0db219fa388dceaf62cb281e1eeea5dec6cff07c7d" },
                { "bg", "4206cdd9cbb0499d824438b8eb8493bf309bc9e5ebdbd994e8bcbdfce2b8a5a7e32f80292c160a076648e84b9de992f2e3e551eee93b76489f97a1066bdf5af4" },
                { "bn", "29d953af30597a263bffe559903dc9a211778ac18d6d1f5e56462bf809c6845feb1f635cfa3b19319657f9267560ffcfc372c2a78aad5712c5af094082b27f4c" },
                { "br", "24363c19e1806c0bf66624893cd06e2317564e07d04e54621856817c7b41e501cb231678a71796003088086b090484eb92e92761a256f237c65bfa4a0b43c79f" },
                { "bs", "613c4bada33933485ce2ee14b35a1558d88b379192d93382c02baa62ff90f247a7922f3504882eecd1d7917e1be09072e32ab26748046064c6e031115a763f98" },
                { "ca", "6bfe4530355eb575d0dcc75cac5591bcd0a3b0b7550e04317c08cc485c63078388617cfa8f5431032dbef94f75fa6feb994aca1def670a76dd72f4bbf472dfcf" },
                { "cak", "8157bd5d94d4efef365528636c99e5cdbdc28960e27967265bd495e407d9c2c002d166133e6cf58aff2d285030b041b7ae1d72a8e11300691402aea4ede47cc4" },
                { "cs", "55817df238c35472a4ef2cbec4846b649dab0b4fba59547236fa110e024ce3ebb8f0d02e2f2909969e28e22b120e4b67436410fa49321cdb9ac1d92ab94274f3" },
                { "cy", "c222ac7601d5bab370ef3de04bf5dc45f3396b78b68e8c89aaa766932592393055166d6dfd99911498b79059ca018a3cf8902100aa5642810073abe6d422fff9" },
                { "da", "90e6f1bf8aa66939d3180bff47da4848cf99b72fb08acf649790efe04562941e13d972d710d61dc8b3b7becf4c0d1ce12b475c35765f4d787d1269261c08e08c" },
                { "de", "84a7ba5e849cedf8b6cd71580ebf2f3553f9b9703122aed26fef513c1ff99994286574e07f5619ced03d9712e4244298d547a974d8e547e44144904d75639829" },
                { "dsb", "d5fb1dd18669ea871f81fefc6a15d1c65908b29e62db9257ffe892f100a9d6c05c519e1c27fb2426f75bda3ea59b6756be5ceda7613e82b39feb9c7bd58f2e6e" },
                { "el", "bcf96e5a25a4da6deb9608c1eaba8dbe6747181ea0589305d7daa538fea2887eb0b59aaea896a1d3a48bba0c19bb4ee87e0379b1c557039c8cd84128ed6c6874" },
                { "en-CA", "18abb2030097931af41d0522f23dd51508917e246dc86c19966210af1ffca4427e200506e0acf94efed267f98c4055842a9545b23e29b3d6f4749247c55f994d" },
                { "en-GB", "2f90132566d21e18bd48e7a1510cd6f059c515133a107efc61a4d249a873404c1a07fad1ce828003bb7253c3b61799ce0ba9a671452af5a1a1784bd5232a9fba" },
                { "en-US", "d2f0aa75672c532e7ea578ed4e4301234c59af5b0da9f7c3fa17eb27d1e6098c4b23b44ee03e767380a0e6f740874fc77825a21cbeb037225d68b5e275227e13" },
                { "eo", "85c37e240fd446f28ecad92f7c578d8d0b17a48f2340b4a78d9e8ffcb1cc3a0dc2e7a55dae272ad09ddfc67b571216df877302aa789c4bd7269c26ec3bc32249" },
                { "es-AR", "525eed130a7563592d7af65e1ef5e4bccfa1d0b201057581b4b9de4aeb3ebc68bd7ce4851721122956306c250fe821601d3f41725801a3239b6586e6f0415231" },
                { "es-CL", "ae5d02c796bca7efd30adfdfb469570e3037eb07c7104d6eb56e81152cce8b0df3fa82b18a8ae59a0edfc95567e58b78ea09654e8196b575c4ac0cf717a6f5de" },
                { "es-ES", "30635628b98e76e86034666685a008ed3d4a5113513be19661633314515597caa86c7c0a60c9b68e1588c9b15ffeb26550afdfe55d9c5c380f3a7224e16790f9" },
                { "es-MX", "b15dce20ac651823ad9323fafb7afb7d9db24cf63232b5f9ea4c43f73e9bb71c6429b539db0df64d74198671a2278f4f97728257bba579686c8faaf0b32a3675" },
                { "et", "73076508adf0c400df83a3f63c2f2228c4a9839948f9e5e9169e56a761ecbb870e45e6a69c35d9ae07fcdbf7bd76fa503c85d33470b938432b6a7155c17463d7" },
                { "eu", "8a20e6c9b14ea41a1e3473dd8eac1c7b373512640c58204c5f469f1971a206b72bcccd57f86fe976a3e83d286d7478fda9185860c5a898ad0d939235d118d6a5" },
                { "fa", "87412c97d63f5685a6cb964b983290b562c87eaccc62259c9d360b5f8ecbd3cb5d61855e01220c7fea647024f1ff6d30c5d208c41b1df139eed524712a216acb" },
                { "ff", "a4b3d20bb9da2cca47cc47038da9dd77888d748cfd4223f02a8bafab3816cc25ffc8383a28b915d83352bfd5926c9bb380ddd27165c777313c286c3bc550d98e" },
                { "fi", "149460b113a64554486ca4e29784616256190d57e7d6965e7fd7646c2355d12cefdd263601e074ecd36f9c590aead74354678b65610c60f556e7aaa2ea94e50a" },
                { "fr", "aea23cba0a17e96cd36ced91557e4ffc50377933316b139103185484740243fdf4c2cfc0a9751ac4fd61e99eb5f510858eb40991ff88affd5e6dde39be3b4c69" },
                { "fur", "e3c2bca76dc2b4ab98b664c922c8536e7b20b1e75d4afef2766440b6afae5f445dfac06b9f0a12b50b5becf77ee111ad8dcf6f7417428af1f2eacd30debefe10" },
                { "fy-NL", "7fe83406d75809c6baa3606219ae4ee638e3d6d9818a8a913b0a18e94eed3514b860958f90e45c55077285fafc99ec5c1f848dcf7d2e79f12324fbd1a95164d9" },
                { "ga-IE", "bb8600cd582ae04a28853c1751f025bc37602325ae79d151a1766f13eae83aeaf441204236c66ec2c8f802561e80bfc0b60f8ee3c4689a2b376af87ced7ba309" },
                { "gd", "27acdc0b1a95876cfd33515caf947cecf329c00ba2a85356491b60a54e25e4c28d4e175cc0975ac1976535ebae0c9fc3dfeb6541ac9eed1749bee4796107752e" },
                { "gl", "08fc9595559e5e22a1b46d35e4e6a5e539b2bcb44adc6f5365bcafcbbdc33593e7860b7e2a73faf27b9cb5057474dcb448f7d7bad495feab62fed1c46ca80583" },
                { "gn", "a223a4135c8c694a9a9be8dd8f2a9aa8b404643e58a64739e36a37953ab08aa332d14f2028fe3573bc1109c9280f74da758983b5b75e30f83f8526acd8f05899" },
                { "gu-IN", "dff66d9ac962d1ef437f69e830eb1ca49b4a30e9122830dee0e23e2244f3230494c8b2e89284694a1fa7c737c5f7c244a3da0f9a1c5e0aec0df0f15143c80983" },
                { "he", "4239ea0390b424f76dcf93dc65715d9e30e0cf1d049646a06830c2b99d9a2c9792156dc3319b102630ced905a16324235e8fa98c6fc7ceb2cf484cf53d6b721d" },
                { "hi-IN", "a8aa1be5be7a74640027bf9d7ac59962645600cb42b722aae23891854cad935cab7606275771c103ecb47ce01eeedc508ec2f80f65dc46d3c676106bc75209c2" },
                { "hr", "b57b300ce9105325238450a880fe2a705f350b4fd712016847d661842ac41030e7f22b5b39ec99d9c322ee5a5eaae8caf7e304a4330fb1f7eab3c2a3db20226d" },
                { "hsb", "baf70abf0abed3775eeb48aac80a8a0a41d3b42c9cf9d23b70a1434fdf6d73d3a2ca52a3d7228c4cfb282d9a6ab20bb601639720336958749bd259b10b66a044" },
                { "hu", "9d046e31164d1ddc9c6da5186f912bd662c4d4b863ff3d6f6581ec1afb6da5c8c5db57155092bb729a4feaaf69d593cd3a697cfeb18a342d0822d2fae3c46d37" },
                { "hy-AM", "08f8c872ed4aa05d0a07184f135692998a672316e5024820fef040c6ebd5d8d8b6821a23fb344449c731f9a27b424eceea23e69b4364cfbbe09a6bd76c6ece74" },
                { "ia", "86fd83e1ffe6510935dd5168971c2ae5be59e68ae505bc386f86e5782c784a85d4a8a40bb1385276795cbaf2131ca03d02e4458b8704439cf2944807a9481894" },
                { "id", "3cabb5fdec02c9008b02b5207b90be2151fdeed373ffecb5105212d1490addcfca58dbacb6fd08aa0c696ab0bd8e04ba0de6a4bed276bbb139e38dcaae84296a" },
                { "is", "a2de9f61354c469bd4f09dfd8b53a278fa2f1304212485d300f3c46894608a53f109e47fea66ba07f03b889464579fade0d93d8bcf0f4ef7f95128dbb5436fae" },
                { "it", "f854ff941f9ecbbbb237b0eb374e526d5b3c16b286964f0623774ca97796d5919b70b3ef63f79561d1d57e87cb9dad51a81dedabe72db0cb7ee89d952d44d96a" },
                { "ja", "cb41b0578745f15cfe633784e5140906f49617e46f31217faaf251dd4eaf2aaa5ec45c02788aec70c9d55b38d91d1fd320154b57c03e91aaf9061176f38e0cd6" },
                { "ka", "92e5d0adb218d06b513c865c9db9626042230e75dcdd29e9d7001de859e2caaf1d980f94cecd98dc114843e45f4936102b5a0ebb636d1824844a0f7473a06a2a" },
                { "kab", "db6452d23e9b8b79b025f24f4009cc9ae61d233e32266a17935d831ee454968b2028e006a2e585c05951a36040fccba476416474da4087e3215be46328563c23" },
                { "kk", "a79976e0e3925289a8a9d74217e7f6d16ff03872b25264a0d9233ddfbfafd2acd6e3db044bb41825027cef8b640e94586c0636a8957fcfd528819fd13a020ee1" },
                { "km", "0db2ad5ac005b7a97d8be2b7f37f43ae810636f3b276cf81e37ca16e1ca8fb81355428558f35dda8a968511c9230c4bc306ff6b83250cb70e470e87234582cbb" },
                { "kn", "aaae937b1d41de88dc1e2eaefbe83a506699f72b74d68252029eec0aff4e5243e7834eed3318a01b1bd62e52bcac2f7d28cdef76ec0d8d16a4b49fb0e16f3141" },
                { "ko", "89697d558f984ea33110a49301470c093a58961068d7e32ade64b587c1827566fdb2ba1aebcc4b55bf954f7d9e8275d93246623612afd9772c29c0235c8d40b2" },
                { "lij", "aca041f202d2ac93ae6b9676fe6003f3d5b71c9744fca9c1841033020d93b7e7623c990134dbf40001f04b37da5b8a6e84d9caaaeac3a9ce0c1b1a0c241bda87" },
                { "lt", "eb52cfc2c9642ce45ddd52b2bf873f7b6d86b1eb70a334915d6a502f95efa2c678c511e2de8ef118a6d78cbb459cf481d44495fac03b9f699e6d3b9e6ec5c223" },
                { "lv", "c37dbe41bb7c3a9d3497f088debe99cae3a10d27e62e34a745d71045e08a9c47af905003a52ebb8609c318e568c138d2d857059c8e7c4473769c28aa91bc0cf1" },
                { "mk", "8fb8d60fa6cf87a301a9aecd589db68033460d41849388d663b3df904129f8f9639213e93d00628a94ce31a9280cb1069843969968216f27ad8bb028c5380f57" },
                { "mr", "38f9f00f84c3be200f26a10f0a547d1708ab7dd538424ff63e872a6a65b1f7f6d012ea0989af4ab73127bbef33e70a86e1b44ae6b75bfe8cf0f92ea480911f29" },
                { "ms", "00c0c9a5afb8b7796883da58d21b8e32e3c1d08f155042cd06e7b3e78ac44a4055141c94f7e6b89addad34caf260647fd395e2f8c415eb9358e42324da7b6b13" },
                { "my", "eae4a8683194620414a38e9657caf8f470b3d8555c207e208fa01e024a58cef5c930f0c30b462f614b6b824c7e32f49399e27dbf4e9d24f5ce1bfb23f80ec6d8" },
                { "nb-NO", "d27b315ab31a761478cfd48a5a2b23b261ffd6c175c27d0c97664bbd23750df9af52a54faf6fd76fdeff8b41ab5d120bec174fbcfe8b5cab9a7352369261b2e4" },
                { "ne-NP", "040b4e2a9072934cc87c17e5d73614aa741ce37afb9cb71afcec8c17315dbd7c3bc727f510b626e2c052a3c33ac7efa31d4ebdfbc8d2aee071c7bae7b4b70641" },
                { "nl", "3aa40cbe4abfd0108340291f3130059d676c773846e06f4544876acd37f5426aeb912694dad620c99abe374442e9f49971b238d17458b934d2ad89cf3282fde2" },
                { "nn-NO", "095b9b22abf997c9a1084412c806554e1f573a2ac1d49b61566261b56a273c6e50c27ee17e6957904b63b327a36e36411ef186be7a7f6073388e0961bdccd6a1" },
                { "oc", "3dafab4696c1298c9b6a08ae26367dd4cf8eaa9ca00a65a9643a04e21bfa0a8e0db852e45ad29f9faaa323bbfaaead648a60f5559cf422ef061e0cb8ccbb0e41" },
                { "pa-IN", "b534522697198081190e7a6740b51bd38972010c49659537fe82d60e315bb3f4cae2bb08f1d2808e0cf9382f9a3f1bd82657897a5e248eaa1345882acc6cd0d2" },
                { "pl", "890f2eadc6da057e923b5b041b3dddbd657fbc772601c3e3ad3bba883f862676d43d61082b4de694cb721f28aaff3d23244c22f25119dc0474ffe39a5b2bc375" },
                { "pt-BR", "d484d319ff4bfeb401128a7ab6cddce4a84fca5af697c934f058a27dc8a8d40e8f4909776edb290371fbcb90cdf96842d1fdfe0dfbe0efc6d21657acfaa565c7" },
                { "pt-PT", "3c52d8c792bbb31f4c6e442d8bc1e2a27868063eade10f0a2b61b05e0d57d7c041d80236680358ec86f3c4bca99c14cb0d90f87ed89e0645aa785df904a02428" },
                { "rm", "6503ff1b40633bd2dc29bd1e69bfc6fd4b77c50b3c7cb99d6ddf18d88d66f031a032a0f30c5ec783449eede8e0fe0bf2beddaa4e2a5c701bfe68dbdb77a4c292" },
                { "ro", "bfa94243d95e51d6b3ae45b32af6080a1a97d598bd2d9118cc8cd15fe4fb5d7913f800079769a31df9cd188a2226cc67694f30a578baf64db2de36b3ae751973" },
                { "ru", "d7d71ac9db73c5689623cfa09a701a80014b6407c633f273313cbfa448b29c76f8b17bcf19a39f3af684d7cea143fc35e1ebb7c251152521d1b83b1db6d5b9d2" },
                { "sat", "260aa75044cc6703b524a64327fe69f1a4c6243e5ebba0b0ed4afc7abb79e94a1d361e40b76466c40dd6714896c4fb3320995b9d83c40826332999c18c9e8e62" },
                { "sc", "63f533a4d64b414a19eb1d0a0eed05f520a475a7b31028d1812aec4d50ba3ae039c329c243ce476e62b0ea9ebcd65f683209fa245b5ab475ed9d0c07d75e2f2f" },
                { "sco", "baedaf78900418d68f99a05cff1d43d74d580cc4cc5567caeb849e59ff6e0749853b8c18a7d760f0735f794ee58ed3abe059431f708a261659730f1f47d82998" },
                { "si", "05fadc0d4100e09f4a9a154fa87f944ba57fc13ad8730e8e3138f6ac02b633dc639cc939c103e815e0693c09a4b7e12597a64ae097da5cbacf16eb2e84c35cc4" },
                { "sk", "befcac4960d4d3401a32ccf4deafd74d20679180d0faa875eecc3aef51dde4f8f6ccce965acac04817390f0ed31c41d94d0b20d0e09f0f106e65cbd602d34002" },
                { "skr", "1558247ee621db67c7a2b7fbbf73bfbb753b70fdce0899f105ffd5a08061ea82d4b5ac6740ed3ec1a28c438af29c2e46fd2c6ff0f16e8eb65652214d455e2498" },
                { "sl", "f3b9f4033e3fd6cc5fbed7212070ea9de5d244400b8c1475d8c17efdfd9adda9a144f805043bcb9a358ea1ee2ffe0b5932efadb5a83feb287c310c2cba49f210" },
                { "son", "a09c35e4703a87492e9643a1df8b21cd1e72630ddc3d63171dadb93b10128d33d35b10fd044c2be2e1cede006fb976e6dd641fea09ebb2414231c3ddab0f962c" },
                { "sq", "bef41a83125157b451a42086a8d5af7311a53177c7c408afaf15b33f7fb2a1805a5ab2f5a5de0762ae187e3520e7cd13dc9cc997dbb20f4b7cd4091e5210386d" },
                { "sr", "2a56dbf93137208cd7803a6ad31864bcf06e4a303a623e8009aaae4a2370a401e00c7dee79ae780ca9e0cf1898a7890c5127dd05b343272ca90a635af860366c" },
                { "sv-SE", "d9dc38eebda11f313582c5aa6f24c0a12080c776ad0f7a5c9fa7b1dba3046583c94f445dbc0b67932041470e13fb2510b75499932b11eedca66cd43105628e0f" },
                { "szl", "7d98af9b837a0529e10edf5f70fc26dc7a0f1a95a3258a49178ebedd53f44f3b76e10a56900e49173befc1ae3f9fa1fe864ebd5fdc76d8c4e4d5a5ea870c2628" },
                { "ta", "3cb3e54e1797c92b024ea3b7fd2577398a96483b94369729c4fa58d0e98ff717e08d382a31014934fa9ad0f9536dba305636d34a5f51d57806cc649a48c472fc" },
                { "te", "ac86dd3e580a6d69891594858ef0cdbe74cec16a6779b8bc5d174d218ef513a150098ba3fae6dbaf8000adf401d30a2c4af65c3424da832e5f22721fb6a367c9" },
                { "tg", "d653495e05390da84cbbe47b346c79cb49cf31b726b571214a0213a43b4c6c63c6dd8947c557ae43009a179623569e32e65775d2e944e71b027d22808f497f61" },
                { "th", "84d2eabd03a873cce14654ca1a4acbcca82b24d88e7eddc69b0bd1195929a6b2b432d223f7abbbfa03ba32eb17e40574bf4cd6e0654dcbca55bcbae435cf115b" },
                { "tl", "10aec1340948f3971cd7194c7ca6759ba5fdececfa4484b87e37c1c44ddab2b7430adb75113cbb3c8f354e262a4a9704fdef9e1418d2517a55983801010c5cce" },
                { "tr", "b64971c87b5c2fd26216c28b361cb3f6235b5c7c370032356bb2066053074fd799fde294cdcb3e710fce22c8fd91115edcc902b894883512f2eaf5553d0919f5" },
                { "trs", "db8e71b70916fe67a2047ad1a41935e97fdfd9e18d0eec3e4a4601e92bc4a9457e8f4c644b7bb9f9be64ef8c773a03c459a4de81e1c76aadffb386b1b15cbad2" },
                { "uk", "e22a38f99cb5ca382c7380186085f7500b8bec33aa70711c119903f2f0a73cccdbae048d6cd1a977768ead1349b9af11dae8d6b6c245e236d9ea53648aea6df9" },
                { "ur", "0e020601e1a302ab4d0161a8cc525bb2f7ec76d24a8ad5d8e56e8e90dcdc4532ff32974c8d7fcfe4608cef7cad76e73d108ee7dbb3ff16e1d0ca7b349a398bdf" },
                { "uz", "875a7bd6f01b02754626824c6f3fbf27cda622d261e22a6e95030f9d30805df59fd46a75aa7bdd708119968b4adb9397f3ff3711c1df3200fecdc64c3ec4a326" },
                { "vi", "a62d0feb5b659b352cf10375d2b91dda5035bfa13eac0276be601bf1585d932fd372af7b22ccbacb318968ccb3e0b81d62ad57a3c0f4111c1b6db1d17d698aa6" },
                { "xh", "2fb01f656393d71681147ee76695277288bd7c525657b500b9ae92ad5a164d74de940bcc2a0eb38c9f85296e9fc346794afd6a9f3d9f5e0ce0c4f73f255bf9dd" },
                { "zh-CN", "6c8c6fa3575ea4e7549497d39ebb228dab662f4878aa1d702f472e83e9ce4af12889c2ca4ae06180901d602296022a0307a13b7344129d90da1503ca06b3f011" },
                { "zh-TW", "ef353be30b2832b97fd9d62f42bcd88e60149bd7df353ce9758060a14a0defdbb785eede2f7dc539313d96d32878d1b26e1dda347f26ad5dd07e76218b7e882e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/143.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "952a0e36060b8e0a79c78638348f2c29a55003cd65a2ca108c5c06a75cf8ded532bbb17c12404c6ee8c94c28d1dd5ce9db5adcbcf915743e84d57a3c54ff9fe0" },
                { "af", "cf8bded942c068efb7afd12b63825868c333228262a1d78eb7b17c15c0467876f1bf20176ac0eb4c837f01e8603b942869064d978243872a454c4e1fbdddb4a6" },
                { "an", "8dae21e0a6807bfc346fd28a9b468f7075b4a16062a833b554a15ed656160cd73af7f9fb22f5597747fafd316c391ccf10344bf0884a3e1b06831449ee5fc348" },
                { "ar", "c921ea18da0db34936b2a82d2897555d616065fd37fc3140c24bdf4843ab2432cd9573c26e208607fc9223da0fb09d8c34146e9df08bf2262f3cb40dfc8ca1f5" },
                { "ast", "0de49f4bb2e7ad09144aa69f5ed6c463fb61a35efe5f1952b11f465d32bfc0e4ccb7b9951c2692244a17c2dc20e93f4d53b93293cd1aa78d5b8c163783a8886a" },
                { "az", "d7ecb8f4cded48d8351b037d76136d7d96c1ecc4e048295378ea63ed00355855e3dbc79081b2029bf432c1795d91dc4721df105112dbc49a871041186d1ec516" },
                { "be", "017f4b9ae28a63cd2e7e791cbb1d3ed97cb5f160c41c9e894a349f41c0cd86084b910d88dd0f17580b6fea277ac96f12fe841f695c7ed7dea3dea59f70c9dde1" },
                { "bg", "810d4f6aad58e995dd99a297bc5df60d7d9881e0d306969b2e39bcdaf119ebe3fd6c76d0385386ee6511973afe77c6bdc75373285552699f45102f1b38a6edc7" },
                { "bn", "8a9894359c6bd90b6b0325ae3106ba4a07dd8c626a700e7a413cea6bd1ff19cf6e7b44c8d14b87c80c95397f76f69eae052097e60922f7b2d99b7627d1469cc1" },
                { "br", "4b3af0b758aa7b446fd60e2e0d10506144501db8f0fd463ff0f82fdef1a45267b6bb9e189999d8393ecd83cc525769fb50fec17f2441775c2429bae78a53a024" },
                { "bs", "20a3bbe2de6977bd22e2034f4d3eff2cd550e8bc428d76fb66c69f646e28da3f89ae20e916fed4b94fa8a6c25b5f59020e145a19f6ec4ab913e3bdf4405cf783" },
                { "ca", "256dbaae0a184c65cceee37feb4ff4943007bfe030ee783d299c03b2aaefd27d53c6940b133354ff4c846dd90c8d99fb20a34f20e4bac0e9c32009abe383b12d" },
                { "cak", "11e5873b12b9ec7b677aebd9d835bf4351174aedce9535b072567930f6a5ea6ae3d0bff4f65a1e53215d22031f874e4df3e5cce7ebc38fa5f1300b0e12d69a74" },
                { "cs", "c4f9ec4b817ed70ddf39fb8f4ab08aa78e6aaf8b3c69696ea1c355b34d91b9fa21478bcb60feb8eada53574877a202944973ca71c127aaf9ff384d74b2d61564" },
                { "cy", "bbfc6955c153a52894774712d928d9a9213d72f13ebefc90d8a1fb0aa96e543f456e65e1667d7e4128ee3b0e6938e33d78bd09b2e2cb68308b32cfd84c06d099" },
                { "da", "ea3ad8c3ffc34439fc950ffe42b479ade06ac463ad6e2969b6901935954ff3350f386f70cab65dce70f9764d2f9abca9f7a3b7d6a776553bd1b334a5fe870f5b" },
                { "de", "40d32cb5bd3a87fc13e3e2413c12e1f5c5782043613689bb2066f0d697b69ecda02f3e1099c38fa9ad9f97cc647c56b989ad6b710777b4e1871fe9ca59f12a32" },
                { "dsb", "8b776ade502607d5ea5741371eaa207d2838ed99ed3bc33d8904a2b626513e7046b18ee779cc49358e0e4dcacedfe8f9a6c6960f52cda24699b5c88c08d1b3f0" },
                { "el", "e6bb761ead6c6cf992c04747bdbe47a2c019f9624650c72cb77e7db1d858fd606a37fd10c91345a9f31d2ed3a7290838e059442b7fd310978e7abe687168aab7" },
                { "en-CA", "3f7b0d2d4155a31e9754d6caa40a7198702d30d96db09cd1330a2eb880ac18f90fd82a2ad6b58e43d960d69caf2f71ddc24218cd55db4a1a923a0aa92d9821ae" },
                { "en-GB", "78430468ac66d3a8adb8326f6b6ea3407c86b9849b93efa66d6875fc23d26bc43a9e93a937fe9903efaae3e91360ca2b39fb602097494a00462c408a80b405d6" },
                { "en-US", "dc0e2f2d6a674f2138fc7633dc6894cb49706dad99135f752c7ec5787af2fe34653437f7fc4f7a1841e943339af02b80b765315fed67c345b2118d0cf4255513" },
                { "eo", "88eb0c545902742180c17617f1c8857437c5028e24c2bf3d60f4b15ace9d9b4e11599d94d4bc73152d51c1287acfacef97bffdffa1df845d1b3e063c88dc23c8" },
                { "es-AR", "43f6795c057bfe21e17a4509ad3ef2343a30b87d0c084ccd18906a32bd6503352e45ea9f8cd6310ea365bf2bd5363f8d24a07f2f6b0bb919b442d2e432cb0d26" },
                { "es-CL", "a87b1b2808437e0c661f36fa104d754c89b7a4702fc676c751538c087140e8bd3425f354d195d1c14bda2199944c30929e8ef7bed35fc38a60e2646e7832089c" },
                { "es-ES", "6e3ba8955ccfe886f21f1d2b0b12b2e456e4e37d6cde451705273fdd2c556b3a927d2808af5bccc9dc9646633c2d5ddd9ceab62207d92062ec16feb166ef5b86" },
                { "es-MX", "b46af94fc17a059cfe4ac6670e427b58cd0072efaddf70733c5325f9044edb552cb2d39d11799cb3e22cae6d16575c75bb4c4645522a93d6805f5f14bbb60747" },
                { "et", "f02a927558cd260f6e5a721b23dd407dbc7a54fa0d5271d81e26e457657fb0f9b9fc787113dcc09413342bec372290f3e823a7c3f93630421d9c0ab16f061ccb" },
                { "eu", "89049baa6684cba233d4151ac05028f4b02e29ee2af128200f9dd3c52902b049b5bf6bc0fbf658fae84aa96d2f16b498ec20aabdd3286c6fba995b4df37096e6" },
                { "fa", "512f017492b0a0e59503f698b46bd2117afb667739c036e5381d6e6df07aa08d26323d441b06a7f27a3a4ae1b2814377624044edc0578dc187f1e8a60c1ed963" },
                { "ff", "cf767bc12f5af9caf3899bbb232d0b58b9e38e2c86da6411985cea5366e1e2e2f9c0af02361d61c2eb25bacea39742e903d4037c6fc2c2e7164512c55771cead" },
                { "fi", "0ef171c2b879e4ea45b8a1572ae051fc8d988411901a342e7d0f03ce4dd6095bb5d48f8df5cabd0d218c8a3da05207310be18f30945cc01aa93a3a0e9e9faeb8" },
                { "fr", "bffcc7774e74b4bf3d790c06d8b53991d7552191718be2fa85d42cb3fe0964299bd63b8e2ff3c6acf78fb00f55d04a85ecb7011c946292022d0d84928633354e" },
                { "fur", "b284d45494bef9d457c1c28f27f21c171d4f4569f84b25d3eb8a7b2f84b0031b212e1e4fb766555a8ba16e9de2ba615d0da5fd416e7dac6228e89a997a9e94de" },
                { "fy-NL", "bcf4c45aa9ee86cffbd736e82501045950e05a9d1349577de47e7b138b948c1a597b55ae6a84facd587fec195b5f82662a7ffc5c05346076f5cdbb40859b2bb9" },
                { "ga-IE", "5a6b0d1e3d12f1ed22ae11a0e939c6cd0057a27cd5d7cee838b9e7c03275ef2578db15351c596203f142000e6f0a2ea9de2c76e3b363f771eb5b0cd5226b15d0" },
                { "gd", "88f167cbfb35683fa5605360d692a49e08c83607d64abf8c16fb07db12a6b135a18a9e4f44b23243b4efaf5d633bc393268967e27e3e16b75b7f663a85bffa19" },
                { "gl", "6109557cb9bfaae652078b3df84c191a61d45631727f86060f19c99c8f37c369d66bc52a8740ad4d23119fa177f1438ee05ba68d03a99a641dba17704bea5b58" },
                { "gn", "9f194f79f5485f8bf1eb2fc8344679d205c2283716298f2713b240309631021d86611ed36518e96203ac5762f4bb5e95cdef89b909475649419fea2e56f81115" },
                { "gu-IN", "9a30a11392cc8ac9958f97aabab07103b6a292d5ef0c2780fc31562b8aabee7870fa61bececbf0794124ac791de4c4c198bd182e8fe757cdbd088f08ead670da" },
                { "he", "e487b0bd9a00b44c5c9a4db0ddf28b5144ef006347360ae61e17fc0154816288c4accd12f6a74a306148c68994d1f10e009d8f093909c80f93013171ccf80e89" },
                { "hi-IN", "2691362bbd301b17a5cdf562135f37458189f54b8a4ec199fde5e8ad3bf77b0b7cb966a6e78850dde99657b14aa15aa9fd26cbaa942053818b625be6f9c7547c" },
                { "hr", "b8b9b9f2e846d1f11c528383dbe23c982640573edcf6bcd21e3d700b4692ff4051d38eafb794441b613c28565b324576a2fe78f496937706420bdd63b5694dd9" },
                { "hsb", "da09f4d099919ad0f2574046952512e611f5b70fb9c0958a06ac71678ec7ae4e9eb38ae8e0592c748ddb0b0998fa6062dd8f2e23948aae2140b579adab1b84cf" },
                { "hu", "16c8e19e9dd7bcb079b487bf11151ec4818b82a4c3aa72f4e0512ce97be49b47be1245d55ab8cfb79fc233450fdf295a0bba5a6a6fe79822afdf786c60780698" },
                { "hy-AM", "0b35e81791c57470e1d6d8462d5d4afd09b1e5a16e56b4d57f902652ac37b8d2bf85f63ae87fccda0bf9b21a13d22fea4e3e772b957d49d4044927ba6a7472fe" },
                { "ia", "56b03e399be52fcfbdd6b1130bde3f72fae3c3e8185dffb8e66b18c1924c4b5e61816991273dfa670075ca5ff00430e9b5ac95f574fecf77c4beb41e3ca16119" },
                { "id", "3a3e513dde6cb2d1b571d86840e34116aba254936b73ad75fcf67b0fb39dcef80b7dc4d3c0b3a24489a454f90251d42b201cfa79f1434d73bb39fc5b6deb4af0" },
                { "is", "7ee59183d04474c1806d6ee71bfbcfc9faa09dfa53d73bf60bd088ede5aca5f028e5314917894d25efff5d280abf44eb99257ec45894aa5ce49a1e71ad5cefe6" },
                { "it", "afd9b3597c93909be45e2301b97c0dea1c393bb64b4ec152502d540a2a719d50de97a6ea57686daaf626d53c951251c03ba7d23371d0617aba507755e26a40c0" },
                { "ja", "4438e8628122c018225e28f6d01e5709d29e5a9397d6c2df473b6e6ebddb10cb102930300546e047dfe436a8281c9ccb3356d4c2d483d19a6c0cc19990842a3e" },
                { "ka", "8541ca9f4ae071cd6e41118a651e96a865368c6339360c29c85c3cab0515ca2a04406ea32c2822919d6d26205e831984c21919b6d5790c0d048767725be623f4" },
                { "kab", "66e15814a66a56522c88e7001cf509e2b2003a5813e0fe6e5b27e2db22a7c6b3a3f81f58aebaa07fc5edf21606b31a0d94375549e97bad18489cdce91da02bce" },
                { "kk", "73bef39d2faaba1893b50d2fdc55989334dcaf97b98723d2befc8bae231668319a958a3a9d04a8f2538af2daaaf22f8b1d3801b595bc6168d4a73fa537619674" },
                { "km", "5ada666003bcef5469e012debe99eb1af99796d5d35448207d0d055ecf999749183f811a764be22e8969e8233545a3a0e4ba996ac5e3146a2477d7595d29b57c" },
                { "kn", "b097527d04d35acc45806eeca757f0f07c3946056620057e50e8fa75af8b9efb51917d7255cafea60451b0dffad6e58e8d1c267b2d7883043b53095932d0ab63" },
                { "ko", "4ea702ae0213688f2b15be367a99d341f709833337f1d0dde1ba88d330dd1874f321138101dccf2d1f92e2dd8fc53ebc94e57ed151a6e7a3c3f6d20911d7b082" },
                { "lij", "20566ff35674ce7e9b0e42e9be533bd548f0e08c6c7f2d349ea89605954b2db71ca64be0211b2a7f77ef65f046dee6e84c5b36f7d2a816e5600e1428fbfde92e" },
                { "lt", "d6ff25c35072583b74c1390ebde8f8125a891181f0ec87eeee90d2d371f1d05716348231aced9caf573332f1c0d57523394dc630d3e23f3844fdb55aa2ffe2a9" },
                { "lv", "f14855ad7dedbd579c7774ea82b57b6da5cc572df114bb618f831ad875738763dcab98574098f6745763fab36e538eccfd64e48ff3c95ada1fb2982e71046dd6" },
                { "mk", "efb42dd968eb17ad1fddd486924aa1010afca11ead580565d420c311c8fbb1988d8d9c8ca80efb08ca1bd88108db1480dae82d3193388c48b32434e7aab8a5c3" },
                { "mr", "323f34a56382cd9578e504d68955fad6563bdd9de9f4fa9bf523d93983045741ce9ae34b0109d2a1afb231f8a1c07a68bbc77234b9373ba3c5105f77fd1d3236" },
                { "ms", "8509c6ad11b6ded06dd9c5278b3f4f81c9ef9b3c68bf2ac39e0f8edfc6c3ffa5a14cfa337a784004c126221c32f7693bf8166dcab7eb203a0a7768a5ef40253c" },
                { "my", "0049261d7eb7e88602061f145439b05e4f8a71c67b7a4f6ecb16e9166cfd2cfd66d9eee27f76fa3046e0a282aafb62090d93a9be280fff2c11c68b71314b9257" },
                { "nb-NO", "4c4d5cd53a0593d47008d70589f0485c770109998e5277d717a33c9e095646ac63017a567b5c1c0874758992a99094672ad5740d3a6b2908325f34508b79971b" },
                { "ne-NP", "a09139b775d1804da80c0b3a5f0626e47c011898f0e5625b12f25d82944f3c6d7908315108fc862fc1e7f319fba422de286193603045ac5d9b74576e41fd8a02" },
                { "nl", "46d69cc6d7847ad07377f999755d645479b1ecd6f61d1464078051fae126e7f2dca14d016903eaca0a2ed6f88064e8f39fc6c92109cc3159fd36824ba1574aa3" },
                { "nn-NO", "b81a2b5793ddbf0ffce88f73b529499c97fa49053068eb385167933e76f1fb28e4f93fccad822950b6524ed73bb5cd2ecf0b8339a55337b7da8598f39dfa1f7f" },
                { "oc", "3a10fc0241fdb93fada0ca2488119ab8bf6b4a023ecb5632dacad92919eefb3f7e37c08a066651d5cb215d54781731d40204da3b774ef9685e1e3a955cb4a558" },
                { "pa-IN", "c0b5c828b22c09d52a2a7b0fb4a58840f9a3d9eb18990aad9466bce58e724f7095dc5c19790be5871adb374abed3139752b9e174179df99c5025d07ef8168a86" },
                { "pl", "b25529cdeac821be432d6883a0f3fbee115a3b25f979840944481c3bae1a26a5875b78eebf49bc91a1492544e830ff39bca80f88dc674eb02e5482f30d18a175" },
                { "pt-BR", "633e92ed5c89b8f8dfa249e83a85d485a87fda18d3c5c190431c37cb73505f01f1eef6a08e5fd88579bf0d1deb5c2f3c9a379b2cc3bc9f6deffacf762ab8273b" },
                { "pt-PT", "fffa22ce64a182a0df88551bffc7913eb660ea8cd7aaa7263378214cc0c273a670a4cc066588e1cc0ccf17e3a2270dfbea917f017deea3adc0d0dec964834e41" },
                { "rm", "1a73eb6c1ff34490fa1940dc8d4a08d5116bad109c6591404ef050f5a9ec56ffe203fdcc1e5cbe320066b810bafa9a4c19791bbbaf48b9a205b45eaafa16f945" },
                { "ro", "c20448449b633c8de4ed9c52e5cf5ddcf04b6344834bcbe30c873a40658f2953581f44fd7eae130dd8b7c037eb34b226e7f1b34b314917a48ecb201f5b5552ad" },
                { "ru", "e0f9d04c6089c2e01d122cf6ecaba98fd228cf728855bb33d8c34600e78a9c0eb40639f0b17079074cd2834f85ee3f59f6de8d8c0b4e3d3286551f3e60399685" },
                { "sat", "19c5dd22fb01b737bbf0e38c3ae38b46d25623f850ab53f8e1ab78d9c7a6819f8df35f4d67afb2befa51544d29d992371b2b6706a6e339aa9f0ebca2bc6b44e8" },
                { "sc", "11d9dd8c1734187433ad1b5f332a98f7b54687d88343a4e3112673b9ca14d40313c857d62d36086db287307e034f5f4e61e4193da3ced8fff41e70b02ef98ed8" },
                { "sco", "1d264ceaff320d783737c312f2e848c75f3da0802b6319365cf6e7fda297afcb411ed13eeeb1f4a6dc92e5d0906235c751fad2acb9222a777adc123a27d5133a" },
                { "si", "f4c3eab164f1bd1c4d9f81716db947c22a2a26a25d47cf723eaacae18058b5f065f1773a59e23aa2a96c90987891b2429caba9ed76cd06c3ac95ff6a89fb0174" },
                { "sk", "a214c126aea0613e95b50f0b0cc982d682ada8f0a0ab62ee7cf7c13282c356eaf0b6987ff90c686e7b0880cb9dfe5f32ebd6ecbdf582a62c64edd0ad6b9e61a8" },
                { "skr", "6b7372f7d7d487ae6a6517450c5471acf57fa0079644666765a23be92b3617909bfac818d86b183c2408345b8b1e4c8b22ffead025eb2b6d3feb5df935ccbfa0" },
                { "sl", "5bbcb6ca9f51610115d21893c49dc1d03e77dc86c54b222f2873176fdbc058e74194d17128784adb4d41e0a4307e494c49b71485aac772fc8d08f7914f291435" },
                { "son", "08d96d3af5e506e59bc2a13d199437c88838e7a45664c03a288d644fcaa0275a3d57fd07904d604fb1ec99ab7798896b9d19c6ba62c21decf92f69be82cbf513" },
                { "sq", "9364175fd1e62e3f607869301624c0620927653055c918ae69dd68ef62313ecd682f826dc87d6864396244a4f89afcc5e5494cc23bcb9881aa98e79cd19f84e8" },
                { "sr", "1454ff93bf30e879952103d2db890bbefc3672ae1e2b87d48c137edcd9dc8f83fcbc8968da526bc3ca26c9ca9dd9e672aa30d20b23cff19008afd70fc2be6398" },
                { "sv-SE", "8292b94091a5004045151151454f9b951043cff5659d4816f12b9b5fdbed4f8be5fbea51a5a2de46bc48c7ac6d52a365cf0327156b4c90c7bf1992280a90b822" },
                { "szl", "110c190733aa4b3b953d2f4c1fc4769a0370843ae47c2b3bd5cbd50107cee48b52109e56490c3942a0d02ff3ebfd4d168f1df5c33e4568e9bff9ed91c69d10b4" },
                { "ta", "551199e32bc9297618f09e505a4a93da153ba5d051dc30577de11eb397be1e5f358a8cfc09e17377a48cdfe8e07d5247c06dccf3802b5ec5c43b70dcb63f7544" },
                { "te", "e22aadd89f034e7f378b809e4db5a34021ed9e6ef590ca1ab65932b1af182ce56aa9504ad1c952cbcb3e041f762af671ee7fcf2e29f944cd6228035aadd5c9f4" },
                { "tg", "f85b510aceedb2f063e5144bbc3577c22ed1235c2c4757de130716c808988227557554c3e327e50c58ef44801bfc469f54531757db119bb94ef5354180ab0764" },
                { "th", "75b626f5c68753a54fc427283ac19fae92f506b336ccd8eabad5c6b3491ba347cb7cf620a960d7653f7b91934f02281bcb743470afde7e9c32aa3a3ded502b5d" },
                { "tl", "f01317fa2d84064bcfc1bc7c5dae05a045ebe94c065660f0f380a8b3bdc658a1e22734cc5cccae3168ecbd353df5005f1af452a648a80da28d304d81f5941c22" },
                { "tr", "d3ca77cee1b7350a394ed2e4e2bebf75ce2693bfa8b2863e18eda00171015ef5400d8427f76a7646bf881c55f19aef98d5ffcccb8d2d844b09ba0e2888ddfa4e" },
                { "trs", "bd50bd5255fdfcf045ae9781f506c418dbc10986b2a88865261c2d90a37e9a3835303287026c338db5e8421874828fb8f6f6decdcc6990ad4a392aa863f25eec" },
                { "uk", "2067a97184b5d13dc3de86c8c043fd4eb76541aece25ec4a2b5a09e36cdf5ead8449e78f5dc4b0bcf3d44adb89157248446ca0b44c634d7a50f6a47517b9db8d" },
                { "ur", "1b9cb4174ae4777b37908272a4ec6da515bf2c8d16d36e75dd5c64b42d1d7f993c30c88a0eba8b6787e03f1165477d87a463ea9b1b12988969a2493cb3a92030" },
                { "uz", "0103e9cdc455106070ebe2071d1418a3ff413aec3b7d5ca4587472031d755f87df0021c5518c10691ff2355758f3287fae85b9d8b92df178951e2f178e7bc7ab" },
                { "vi", "7a78b678615c958aa0f77d95fe31422dda5f4cad9bb90bba602fe80f6268abbea5505ba059503999c72d8e417be4d7ee9f73fcb73f0313986c4b8046cb560d58" },
                { "xh", "f4970c507fb5aa4fabc530b7efc9ab4f43977186fc75fa3731b6d26c17f583ad84a951418c21b60eb947fb1ca08a3f5362d3a6e95b7c25c2eb1b3bf02a4f87d4" },
                { "zh-CN", "7da9edca28424a361cf749abfa17b56823d5aefe194cdd6917ad0f071dcc3044686e926a2c329801088a32190da4f9d06f556b01616ec7ff1a01a04b4d4c28d7" },
                { "zh-TW", "8eb4ddae68a48f8ffe2e0ad6a4dba2b58c498907d4362d93c837be2a37473e36898d60dc2af69d56416a142e2c760a75f7d3bf0fd4c3eb38f79bf64c6d252c36" }
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
            const string knownVersion = "143.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
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
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace
