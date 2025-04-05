/*
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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.9.1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.9.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "c184144e394c575833d4375fe4126ae909506e1df5f40f355774b92e427263891335dad027b652f8c4dfe949f243b053261cdbd72e3c6f7b89c80e07251c3881" },
                { "ar", "75731cde524118d1d17d2bbdbca55321b93f8d8ed479954c95465cc44b0678f98aa9c0880564f058003f03a12ac147619428b91a84bd769d56d22a12e969e201" },
                { "ast", "ca40c1951397bc613d0d717de66f2e517599d509348096f35ec56acc382937c036d7cf46525dbb3fa180bfa6c105b5043997d91a1419f76a1d16d1dfaeca6fdf" },
                { "be", "3600b5968f397de933198863c65ace6262b37ec0d7da33dfb4efa3de6d21509a011cf184f23a9e6bfcbb9e8a56f8732c301efb5dd6b2fe6fc0ff3a2e41867de1" },
                { "bg", "319c2b1c198aa94e8ea4efe3ced2d872b3e6010bd01cbd4ed407072ac20a6f6c11a86399fb93e29a231333a18660ffdeaa05f9f0c191c9db451db8d240873c28" },
                { "br", "e0d28ba70238616595a54c6340b580d2fb812747963783650a1ff64dd491c9eb557c21f243ad615310816f94fd865536e256bead7ac5e6bd0218dcc0ec204638" },
                { "ca", "f494d61228866b75da19c0db8a164998a2ed2ffbc1c48cf571284b722bd4043e4b9bb36fd5e3e292eeac8c25cea87db02eede5a049426c6f82637485f899a154" },
                { "cak", "3b84aaf89e9fda4101097b32c947b421153e5b3044e9279934fa974afeec45b9f37aceae2a3bc4ef2dbd2213480336141838716811dc281dc747c87cef06288f" },
                { "cs", "f6f2c6138276573a3e2205db77673cde7e09d94c3be77240a66018ee09a53a3e2e8bc92deee712c2803507bc1e5022b02b4c68e7c513053ed6f1bcc015dca1ad" },
                { "cy", "a9d56aa3c40188b96625a805e4dfc1373a5b96572dbdcf42566429254261d820a4e7785f1d62a52dbb3994a28011944818ca513857f118c44ff81fa0807983ae" },
                { "da", "ce5313a36043dc6dab96af19cc34d751a30bf3e3c25a7b9084a540e984e4a1a63dd80116d3dd2bc19eb104481cdb78f4faaaf372d5295568e250085364b0d08d" },
                { "de", "c607c0977e1a5ee2ac19406bebf2339a6aeb2d125ba94d5df14799bf228ec5b9425b1e500c6ff2fe25e0541ae9578b1d58357ea334430b57bdc7a8dd3b61e15c" },
                { "dsb", "b0e2531dd4a3cf75592fee0f57c89112a8196b9a1952be37628aeb84f3c5cb763b405517840553c8bbaa6a073dbb0b6763e1cbf5948778682a16b6eed796cf69" },
                { "el", "b210d3afdefa92d67b0bde71e9f1b2bc05bc97e55779d05e1f4004e327d6a34cbbe9219cce695bdfd21fd351f4cefa9c7779a28c9841483965fcfe6e601f9d57" },
                { "en-CA", "3ebdbe41fcd3d7a54c4c8d01a506e9d461cc7e210ef4da629050317438797ebfadb54eaa74ed5878ae336accb070bf7c925049e17e27ef56255d5fc5f080297a" },
                { "en-GB", "c4e2a10fa7231ac7aac679e69b8be88bc4674e64c32ef68d35ce6edbb164132e15b0f123ec60ad683403e488c17c378ae97560e052eed59645cdeec176a43e16" },
                { "en-US", "131a615f6ae2f2b0ba2fe6c1bdea6b7cd890c831225bd8c16bcab8dcfa94719247c2b32978b2bd612c8f11d37020c5c2ee0d787edeb22d0e12ffc2f55a042e8d" },
                { "es-AR", "1800289786b749f16bb0aac0cb2c09cc4d7acf2394a30f6038a0687d6e688a2ae63ef48fe15f400cd0487dc60ebb5deb03b1f8b422acb0b93dcd40f34014728c" },
                { "es-ES", "544ce73704ff77ac5a330ef1ccb882c8186553e8566a1e5a2b2951729b0356cd1d408eb8390f09c1a274b585937308cba50f780177b5fceb5ce1af8b568ac7de" },
                { "es-MX", "5ad367c0a5a8defbe0b65d38cb18d34f03b70208daf444b761f077184fd82837c030763131f96fcbb773e7bf64f2c9da6bb44c14c4d645fc31290c51f1696243" },
                { "et", "2c84ebf3659bd4f9f4937b2341d2f586e75ce3257cce697f6a75f30f639f2e5ce6fcb69f0c6c33af71efb55bb9451e95a2600a60dfabc82c5b7dc5fced843021" },
                { "eu", "13a7909ead5394ca45dd554f394ad6f6b474a86ece01e049f0faf1a4d7bb03e9100cb34e517af8ada01332a14037646fbc1db953eeae2385f4ed9e5521add276" },
                { "fi", "67e189aafba6ccbe55972604e29a96a3502eafecd92e5c76e24a36477c6e10dc01148e30e483c0416262d4bcac67b2b1f8d5409716856f1ff94e21ab369d307b" },
                { "fr", "195b098c01fc7cb8f72985b1d4768a902d0830fb4e5a5fbcab7fabc53dac6b3bf2a7d3426c8afa065cc7de8b6b08fd057b4b61cfe11a2b0812e5e75f75d0f13a" },
                { "fy-NL", "38337d0035933bf1a7952f88c4dab9484e3fe2192a22516632a7058baf24221a9cf53d39f6a05a0a4b461769f1374b3fc354f6243269597c5001d118d093d4b2" },
                { "ga-IE", "f41113b5591d24baf21b3557d832d192c2294b3e23edb1eafa2f6a9e7829baeab2316648940eb7c800a9e27ee2d57acce2d9775c7f49ce99b59b9bd08dcbd790" },
                { "gd", "cdbace57a52d75bfbba00ad916da5c205c544d8f61daa95031ec27f2cd72dd212eb3e095c71c9227fae3d2f3af689e53335401601c707da1a5aa150fbac1713d" },
                { "gl", "4eb77ef5a53c45a575010027ef333dd10e63c2d71c84e83fe89f62ba05281abbe13c7fb66ce928e51d8daabaaffce44810aaa70fa5e56830565ae5aa86315b01" },
                { "he", "ccb57f81bffceeb7ef8e2af82d68fe874131accc65764801d328cbd94831ac6e26f6c57b8f0f45573554e39259abc2575eb6d893c602fcfc28ba23b079ca9c8b" },
                { "hr", "4a0b714c94d782c5b44a1a1c4d6d5b68d7c5b010c748a388daa460b588415907f7eb7c668989c2f9ae42e8496a6e6b3c742a6820a4b7bbd91d8381cd6d42c1ee" },
                { "hsb", "07af322c4049eda33f0fd3184157594d63ac5e7a23c2e91a1c1f8cdc4003d3890a1d41a6fbdc9b5f08fa558cd831c04de8885c6c5209e0839eb4acb7e6c0c303" },
                { "hu", "5e4549ac1bfa9b1d5de9249860958ee0c271e90893b860af4d1b31f40173900c765cc3ef1852f22e2808e38e04540781290292d47a1f0f3a7fc81fcfc153ccb1" },
                { "hy-AM", "aa5e745a85796e499f3dc340b9b128ba8d72e50d5ff027081888b7059846076fe0e3f95e1488ea8eb0e7135c7424f458400ab0db5075d27bf7660cda9fe3ddc9" },
                { "id", "0ef0a9f3a548c01dbf1154e4e324c3ce3825cebb440dd585f396174d1c3ec7dd44f91df70fd8f4c52fcff2cc21e057bacdfac8cfe60d69bb33487b8a8666ec30" },
                { "is", "6274d0388c7833c81598cd55e525166b94cffa2ec748b67a17f675d6f22d5a05fe03340c9c0a6304350c0e773b60fd88d61686113052e046736a94d16c8c2cee" },
                { "it", "1982107074f680738c813d7a8dd82615bc2a296fe43828d6bb78fbf83b8a1ba02898a78dcaf82706823879d6ec38a254599fba69c9209a5bd36e553e13d0c21a" },
                { "ja", "34242e955518d1c9dd9422ea5e41a8d688dc9495968239487b31361ccaf229cc42b3068e392ad8ac0d2d0fc099dace132e8da41b8ed675f9bf48fbbd4113d487" },
                { "ka", "42c04acc8962e4f965eec83bd8007cf84bc832ecbda466b447c400abfc6306dab0adecb4fb857c0a182c3f7faf1c1924c03cce0c3948251795cd0581430f1e50" },
                { "kab", "927349ef3d783ea67943121bfe9f498b0f0a8feb51b23be715695c82f30d1a0a2236aa40a34d3ea57ae8c4929e4ce13f6450058f03a07655b8758895ab7cede4" },
                { "kk", "9aeb1da5ec7a427d5abf1f3792aad47c7e1c25bbb5ce503f77472532615ec1db8f937eb3dea684338a9b99409b3d3bc2cba02bf3f5f5bf7779b4eba78197455a" },
                { "ko", "f35db11b5ed3a0655967890d5bb821879da7b5c567f51529b04ecda30bbd39b00008c585c399f7215b4bed92e236b0e0f5cb9324a38a95b892b776389f70f52e" },
                { "lt", "b2ff25bcdf4fe573aeea710ec259031593a7edc65470918c09bc94d391e7913676dd0826111490b8bdd6277d786c0a147dba32879527fe068ab8d147628cb76c" },
                { "lv", "743bf0f80c7050f4bec415c03065dbd7e347630a6fba698bb6a14824b0ff48bbe95408341d4c4a92a02f9dda4f5f9de3a76467347f1fd9c6f5d9d9e6acc64d55" },
                { "ms", "033002b9b8418a8c4f184844f76bd95043ae7ca85b9d3d5037e881e33d6b8ed0704c6c2b1c557f5689c212a4cb868bb0f84edf4763e899e2a132340ba0ef780e" },
                { "nb-NO", "ef45509c068bb0ad0fe19c3b19a11deed3b398050c003e011f9b5f56cd468c35834a73c15e70385c2899e64555352e1a7910e954aea696b8b87828053bf7f76a" },
                { "nl", "5f241a6759c6b20518430f11193c1bfa3e5be951eaa58c02972adad0030eb5a521dbcc790184e70c95c53e562c0d15b2f43c3282f15f199c24b1d836c9830d60" },
                { "nn-NO", "66b5f3f684f349f9a335e0dc279bf181168f6f17931842860c2b31524a0891e483ac1291cf234344bd3f77d3430918e33851a478ed1a2f4e2421b21a379001e8" },
                { "pa-IN", "96e77dd152a46ddc6c625a0e6619ae09fe0481b8585fe08574bf9a8149341f112d0e8bd0c14884307073bb03e04cc8a464131a983b8cb0b746f489333a110025" },
                { "pl", "5b336760c7fb0cab147568f4279dc5714644ba4077946527379d115016944e0042e42fb3e2b74256116e2ef219f59f81f5c255e0680fdf0486ad2b808797d6d0" },
                { "pt-BR", "5bc578ec41932d31cfb852fc7e5bf39ce411ec2f1d3c028db60ef9c9e1e7fa82ce235f03bb4f8c6255bb9401aa2bc075abda19fd727b51e382d5a18f592538fd" },
                { "pt-PT", "16259e702365680f8ffcff4dfbdec6f602e9f3d7cb6227efb05adab4f9a8e7ae641c6a31280493b8690ec97bfd200fd0a8a146e84c8c387d71c159f76acba22d" },
                { "rm", "be3173f9ddd36a73b0abe01e8a816ee61159e7a9663879a4ac6f841a44c1b80dd8e073458b562cd25d5037ae70aa12c210bc4386f981c714fafa3f7e2f940785" },
                { "ro", "08c4107e5192336b254b74b8f5752982a95d524911167229b8fa23a2fcb0c090849529e73babfba4b5ff8a0d84cd58e035b0df3e14684183172b35889d0035c7" },
                { "ru", "2c150c006b59626e24a4650a3d0fb084ae4bbbad7d1a9b49979a84712dcd7c8600dd5b0d1f7584c44b8fdb1e106bf58aa9c29b6c1fc06415d49c480da267623b" },
                { "sk", "15776a197df82922566589120a45e25f1f4d50ef9efb95478e3051641b97ebe93cb54633bf17fe7929d1822af0585b8ae623411238829c2ab1b254df256bf62f" },
                { "sl", "d42444a48decfbaf509608684432a6f11a035c0ace963ff3d6fb23b6f59e839a5b4eef29261bee26575450d6e6fd336eafc9ada57e6f682f7f1e1a43d21354e7" },
                { "sq", "286e229e15f848c67a9fd79242daaf49dd62efdd4dd473ae55a6c116b55b00d8e5fae9c17f7a53a6c5303274841ae8431139d30c54e384eab9f5b17a4dfed603" },
                { "sr", "edeaf6ed75ade77f0ed498a2de0a948845cf2361ec3394794b97de681377902c8bf5c642b08b3a0fb33e754f89d9f1fe69de6777c77f17949d39799c66e9babe" },
                { "sv-SE", "6540efc4c3a030af837b726d8c3a6c7e2b6f01a480188367b308a8f324fdd6c99f71648596f64b4a9042974c1b82f80c93e40def0d53830354d3e4366b3945e8" },
                { "th", "916bd007da6d6c4ed090b022e8bb2a2ba8a1e8ccbe36030447aceffbbf6f896aeaae54a819350cf8df736062f658ff244b9fa373be8f228e68ce1b66f250cb7d" },
                { "tr", "8f57ab359e23d626163fb66b02d0b13a20b279b92ab44c88b9feaddd04395f410f1fff40fc6da5f66c8dde07d5f7a24fba96484e63c46e2f032753bee43be69d" },
                { "uk", "06dd118dd5aeabec6c5d5ed75d123e8d86d15cfa714fc54bd53135bdbc2a7b6d7e82b8cea998c675eeaa366a638b9aa0017a9cffdf66714a5f78ecb69529890d" },
                { "uz", "893496adf25effab9c8ae975a263342f520ed3cd60dc57cc9131f71ead1a9ef315df54617a270966fa424dc59b2154da810ec01a944ce8e5b95481b29e458a02" },
                { "vi", "566ff8d042a829002d7a29f12abf3a45d748a41f9272a0f86fc332f1834862cc651abcf9ded79a0c6979b3832eb0b74d9e9527600cc5a339c5ec25620fa8322e" },
                { "zh-CN", "20cf83554a502ceff6286a64ed94d4204ab3bac14068947926138746193bd9cf692222562965d12c4c23cc2ee7de78bddaf40c6a4caf86b3c5fc9b9f9b800d7b" },
                { "zh-TW", "5f4a2549f30602316bbec7a122413b172c90c79f7e5604d11f4dcbe521c29bd3041b386a3e972ec96a85eb2e9278439f6c2c469f7bf0cda1e7abc34fea32b176" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.9.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "c41e2e48f673b323ca225822b6108c4f23cabb65c6679dfba343ebd887b1debadc64f4e155fea73052437a52019acd53c8020f93ad4b02501a8402efaa181ab1" },
                { "ar", "98535f2d4c7ebd3d9dc31b4ccf9b71243577b755bfd4130a338d948f8009ddcbc3377cd54f6e579a306add697f228aef1a1fa5e9bc50dea49d64e0034db7dd4c" },
                { "ast", "7dd94ff04cdb8fa1a7827ff8784e90d8f587b48b0c32f8956dd46fd5ba08102fc3e4d7e8254da32cd9b11997f2088286595717773a38439674dc73395bf03fd6" },
                { "be", "fab8d3bcea29b7688441f74ed678ffb09d69184a05399ea1d04856fd6fbe9eb5d1280c95bfe5d9291417fcb27e42addb9a132ca3aaaf8d59bfd3c8c82d276d68" },
                { "bg", "d175bdae2310551bab403d478b3c1913cc5ccccc96e06189d6d98ef4d866b059489355cbf2b7823aafd11c5ac4ee93a4c4f39df730eccd601a6dc51bcee4f46e" },
                { "br", "3557a061e19b26bcb09030409763ef388b708224c1c570aafbcaeba503128ea15d271db954b8d54e7a5e7210fcc33d8b43def4696c8f7f2263a01f12c51aea1d" },
                { "ca", "38c3ec10f5a8503f4171795ab9a867e609d4c67169a0edf18142363115406730d92d271a2c44744d3d781e27c31d7c19ae53c77a408463a1ed881058f4137cb9" },
                { "cak", "0e9c3b8efbd40db6cf76155c69c6b5018d335d53166ecc577200eaa454fdffae20cfa606a7f9eddb46f8b0d8f5542f1c42fec2c2e618e191a45e16ff9367349e" },
                { "cs", "419835f340bfb1184a7c8299d9de9eca25d4453999057fefa9861fefe16722dc76c558913f16407f07fa6190fd45c46e5383f939b7a905f4df92ba1f8145e812" },
                { "cy", "b2fa1b03c32e6e21f2b108d242184c6faa59ddf1ae168d7e6c50f4685fe12347c6df2f1e4c714d1441e459a489d1952e7d467620d9b8d53805eba70d95577b7f" },
                { "da", "91c5b0a745e642c3e97a9f0b7b77297cf48ca4f4084c329b8da58f0ae48c8533342901dd0b53b2820edd59ddbb4e0d9fdf85361cb06a795ed966f9fd7a49a23f" },
                { "de", "8a64af80598750a09d2bad3129e5a86846b4eade48af7083459fb1989867ec98a91d86d4750836df7f8d6250bed696021fcfbc2653fbb386dcbf453a110d39b0" },
                { "dsb", "35b43a0b6f88a1ad62ce26d811d8a394e578db9fde982f436dc85509ec6575031f2b63c9063b2c7e3ccc79e266af2243b82fbf6df28eb516fde92241902d3151" },
                { "el", "b9486d7d258a2df182064d08b5889abc2b887d31f88041f4063d10f7e27221d7cfdb78946a7a246771996e9d5c586a4e01e5a7ef9509d336bd293187c907cf16" },
                { "en-CA", "d047218f02e7534a2cbe685f594e32b068917596690b1d2ff1fc5fb7f7b5c3121f221f2c2746a27c3c25a315c518c29b0abf40166fb6df45c1247ba3a123eb65" },
                { "en-GB", "f4b0c49be28846d384ec906c07c2e41aa6196cf0bb8f58a548fbe50b37364c95ade167c52a4e959ce8578bce8d12ae34dad0718dabb05547c51a56d4376f97fa" },
                { "en-US", "684a3cb80fe4367fa7ff64b10e944aacd60e07c9e8e99f6698d21ff7b5f685fab35f5f8a43ddaa9097af84d1b851a26f01b932fd7b94170dbe6821741cf9c09c" },
                { "es-AR", "66a1f343386df8e10be1d41e26dba757a26d6bfa3a0b548a2cee25737b55ec1e4cf43642a92e2eb77d21092236e40606340567fcc864f92a4f1646a31983f566" },
                { "es-ES", "843d5cf77d6fcacc9e78b751dea80c78bd1c165aa5a8af62a79e1655208864aa75f65fba3f0ce94b479cd044e65aa29fe6cd47bba2902439d7580fec4a08a9a4" },
                { "es-MX", "2886e103bbfe812a5c48bdddec10d1c5c3e7c6354d5e39fb311deadf8280f65d6bd80e0750c9b5360a67a613309ec1cb047bfb614f22ebe6a0468f5c66a35e5b" },
                { "et", "d5d79ca99692992c2ced0756fcdac5e0ebee301bbae29784ef1407715e19d9f2b99b0a266143266acba07622300429768343bf64180b3ffc6f9d5f675304e9a5" },
                { "eu", "3ddc27395100c79d92e28a2dd6a07e92bc4d787aeb165521c177dac4a7df2e6aa88f052a20b45abfe4145ce90cfec1be9f4a826e93864e9c39d66def4afee08e" },
                { "fi", "6348bb717eaa3e3bb5859711bb7c174be50b52d496b957a0f67f61b26780b320a901d8e875fac39aae718c5c6163a0204c5bb17b77d327adb01dc0cbbad877ef" },
                { "fr", "2eb5e2013596b1c91f753732f6bb705520660a046e0c1ef06a8f726c0b0d7a17ad2bd4f8a67dd179149602e6c167761a57cabad3c8aec7ff78d18f056ca76e81" },
                { "fy-NL", "d4a4c1fec6bddea3b3c9b1eab1750d7e033574a489d028179519483e78ba3539d521c1af82c22eafb6f9f2f02f2b4e6cb9ea08377fe747867eff166cd7d43296" },
                { "ga-IE", "3f26c2168701df1d42d95d79e6be8ce358e0028b277157bcdaac1dab0acbeebf385bedc9151e7fee54a6f8edd6ddaf5fc11d3a24846d4028c4f0c2d3ae6a823e" },
                { "gd", "404f3a552e5dd9cf86896927e0586382a38f30190cac7a8fc8e22456410657e8a57a1d005665f46f8427264d187dc8bc7a18259a1583ac15c1f589ed3318e3d2" },
                { "gl", "fb1a352c057fdf3e142310d09254c496668eea9ff1e61b62e478a509b491254e1e011d8f2bc4df4ae9126db5e22d0d393213620e32634adc565d395bd3adf45c" },
                { "he", "abf8fd2829c057b23be13f24a79d4730d05ed8961bacafa7e351b1ceddae6ee6bedd805c0df00a0597c7427d7d347bbd569df3715b06372179d47b893a811c97" },
                { "hr", "58c8a700af747f9b9b058f1e8138d97d862eddcad7a94aa29a518c5979c9858381c4ccbbeb5b2e83191a64bc2620d60a7668875c66569419e74c9afe284563bd" },
                { "hsb", "523570bf7212a51b1dbfece4ef7a9514d7e95a5523fb60ace920630d4060b21f5addcb7892172c87868df1048b3595e112e7267d225c7efe443377b0b70db0e9" },
                { "hu", "0e4a3d6d8323e1088ea87b0e9898bd961caa3464ff417ed15af10d29fdc4f7839f06d96f00975f443d4f0f1f9843c26d81f7378e6eef9c0b01ab54c061ff18ce" },
                { "hy-AM", "e2e06d8dd8a46886a753f72328dcb8e4079b9237abb914f1f2a057a37738c5dee58a947f9c5ef78f7025904a2c7097c250480a312b87841957227aa828e48a46" },
                { "id", "e7bb1b8d825520652c0117ed69f683de8e1425f620244234df4876aa9920b61a710bfa3c02e53d73d1cf86b296c71dac196d487579aab499be34d18f5f71d47a" },
                { "is", "5f0aaf401661a9ed466a9d840d5083ed4926e0a46969dcd232b891fe126ed691138ac85b7f8c53980f211320e37f46192b6345ccc408d381183b46cd9aa9dfe5" },
                { "it", "d26c9db43614736ef08ee939b75ad1e0cd71ab4bdacf049892d91745c57f63061f66d48d21709bceac32c5bb53e6f7b372f951286405ff55bd4266c136eca1e2" },
                { "ja", "197291e982624ae7f84e0a13083b600d2254b9227a508820766531e8545ffe70f3d012768c3e018586a42921f30d73b30dbd33156b788c03f4244c15ebea0fe5" },
                { "ka", "4629db029516a2ab22515ddf1ad1aea65bce5240173b30e3fffefd8904723fcf8a76b68d24cda2d6f5bc16635fcf82b63d0507317998c3d696f6c85331a0477b" },
                { "kab", "d740b17c1c6ff96f25d4f92c38f1d310231aeef442d52249cfbd337c3d9e1c4dbe0e637417d49707e2faf38b7a436559cf8e9a7b3fd87a5a4b440554689432b5" },
                { "kk", "26d9dcbb2f25a9fb3d46e12b5997bf7dd7fbf82f3297ad00ef427ffc47630224c7b948d256cb515e62a7ce1dfe972213838d8319fe82ad46e2672b9dc1015456" },
                { "ko", "14142ac05bd6968ea5cae5d727fb4965837c3610a61adf60f9a92f23364acc1f4a45732a6b81ff2d53191c081abe5eb410d15aa18ce307a9615b25d4696c1b09" },
                { "lt", "31ca3f2b13c6b1ecf83e5837d7678cc6dbf3add7bb16578a1f0f014a1e6958d682e0a4143fdaff1732378d8f44de0ed72c3422888a992660bdff69273fb48a2b" },
                { "lv", "66d6152799bc14313396d4de4fad1e35e0d1ad5948db0a47c7d1fd3dd70c90ccad82631ceabb691d1b71a50a8d72f3cc4beabb3460155c51abaadad0883595f6" },
                { "ms", "0fe76d373119bb8339abe6e2d90ebf456b4808a63eb95eca7811d4bb635493c6a2fb9094dcfdaf9ec881732f8063948a55545716c1bfaab30c9dd3633d74c98c" },
                { "nb-NO", "bfb5451336c64f968fdfcccfc265d9e458b3e828a07335bf6ce6e4af4646fac5a3ad66f3a3f8fbd8fedbd93ace26af2f4c8262d283566d70b2a8205bccf4a984" },
                { "nl", "4aeb24e71f99a7aec62198eb567bf68542f9d7b13d4ab3f26af1fdd6e0ae561cd29c6adc6a5ac746915d6561a7626972a8b804e4da6c5712a2ff4205b110d670" },
                { "nn-NO", "36ff4141ea9ccd1263b368d2209355d72be5dbc0192bdcfdd96ae4fef92b99e8d0518979e4116139c4360450121df30d10e09ea810914bfc314ebed4670014c0" },
                { "pa-IN", "d4cede8538b57d473b9e9897146942926129f5d97a1daca7c564f00547f12ad8fdff16d15f1ac362bd0c2a2fcd0c42a10f4c70ed5985e7ca3e5a701d23dfd865" },
                { "pl", "dc2a7ff2c736cee819a2214aea280e3dea974b86038251bede7b09f35695d4391abd05aecffc44ca076f88e68f0a463e2e10431717990e0d3039f23e3f9960ff" },
                { "pt-BR", "f781319f4ee25945b86f141fc0b0e9954310c52b148b6bc01e6bf0150c604449bce8735b87fdee7d621e20989b498dcce6581654d82a803f17471bf6b0bed2a3" },
                { "pt-PT", "0cf93557a0315d0b6370bdf002d80a1e5cf136e501501c3820156e7d46039f3e1046c55032dff5b7472fc14db8eecca318caa4752c59ec71a3edb1d4b7c1e974" },
                { "rm", "a6350749bd32ca7e6dd46bc95c1991875de8d2e9220218ea728c5548e0efaec40b456e393246f6bb436898febda9df60b117236d7bf0bac1ec5e7682c957e6be" },
                { "ro", "cbacc0817420fea63762e5abe51028a3a2e8438be817fc7da0f6da0ad354df6e47f48323baa9ecf07d2509c8972cb6915946eb5e8b41d69c33f4a7a44816c74b" },
                { "ru", "584a28bd7fa5e90ac9c2cdd1bd88ecc8fe3bb7423c38fe2c7afbd38466a3389d948f9a64a9714e3677d664878b7fd13e5385740ef182d1f607c69b83f061187f" },
                { "sk", "55c619560e5cff2a789b01951fc4791fac88461ca7f75d31edee1af08aa4e97285732e0eb2b0b718516400fcbb7ec9bb0439924fd4b830b58f3a7bc6fa9d6896" },
                { "sl", "8a6158b9b4839e1d136b7a235dd3f2ecb839bb3750095503ec59ef6e24d0756fe747e10aadda05c2d99c54abfa8ed9e5d6018afaf96c8c0e9a8497093c0d3ffa" },
                { "sq", "bfa7a1c791a4f5b2fe6062aa2f9fcb63fd243f4d85eb242684ce8bd82c485987a5784bd768ea656901b13f884c0866f42a494e92f31d070f8789a2f8ab67c8cc" },
                { "sr", "6ff56f098cf38a55ffc1955380a371f70d06f78222c47a1f1c0356404c529b9d18071a32fcfaf040d9a39a8e5f769263f52648ee72bf2259a31b67a696ffc100" },
                { "sv-SE", "7e192a687d012aa5f7ad9e3169a400af591a1494ef75ac2075ed466cae3b9e8a83fec2c1d45379228d96a021935f357f19cd813c61a5490fab8c8b1e7e47f004" },
                { "th", "e037b7fe9515cef080539ce1f185f3ebbcfca23f22717a4133f3600cc826d228b3581bdf248cb871d97854ca20c7ae024bb626f67bc5ac8dcc692582c6f053d5" },
                { "tr", "2ccdeb82346babc786b0bd08fae3c9dbfaaa03167aee72d909f686167e63ce6ca3b5841695ef63ab14d7ea123828a4f712fae80cf79af0de1cee34d4ef0dfded" },
                { "uk", "70f248c9858d72a930210e66d6ba52b7074d2d2b180114e2d6542485451d13996cf2dfbd1ded853ddfb60fdbdef5de21c9c36d558f040204ab39c296d434555e" },
                { "uz", "50e5df96b4fe782dc91bcdd0da5d7abaf829b04081ccea3769eb94270d9bf985365cb0bc1f900a0903989e8c53219cc4c963796c910874dfe90af918b4c22676" },
                { "vi", "5ba2e6417f7ce8367c76f915383bc7eed42f3d829d2e0aafcd7b3c8144bf171be970d25646325b18ef4e344db95de55f41e5cfce476fc6223f6adcfc783889dd" },
                { "zh-CN", "a9f1d2a181790b69f3b2e1c22e0b4e4de55030e374906af5b022e0207c8c497d14c41f0b976374a29dc5d99161cd2c69616c8706acf882424d5535ce8ecf5c6c" },
                { "zh-TW", "3b3bdac63b9d810028d39b648e6be67eda9f368309510d1585ee790330a1c24488d68da286976662ba128a71da696f200f080706368c43b8cd5c2c751f5795bf" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
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
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

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
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
