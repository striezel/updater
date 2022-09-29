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
using System.Diagnostics;
using System.IO;
using System.Net;
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
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.3.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "46167b68b861664a61d690d266149c122024d7c9052a5f721c21f61c37ae4e8a374920411f0dcc08ebcc915931caa9eee7effb11d5f201d1d8e219541450c5fb" },
                { "ar", "337c4edda6b31f27b46c020a34aa57c1d37b8e12db0d27baf2c05090d3ce7ef310373a80cf5a993cb70f8b0bb7fc0c919e17226e3111678e28fdc94655d84b95" },
                { "ast", "fb1cd53558b79635c272cc80f0b73f14bce84aa06b8f91b4d45fadbc3c16e68e49a601cd41c1ded28db61ce781d63377b264217006c538f3dc17bb39c38e2c1a" },
                { "be", "11173939330b1b0b1d49713bc3389536b856c00858f7831fb61d5d79b758cd3e82ed0e9ab7da639cae33e4068cdca87d56d83ce263061685b4bc500490716ab9" },
                { "bg", "26e17147aff5d797584a8cbab5178addcab3e2128dbf9c8208a915968ae44b77e72a55ab260ad34de6a776fef8f2d1d56501ce8e3a37cac912b5003f0341990b" },
                { "br", "93488776b4560766b8243e96ee420ef475e8ef2356ed652696d045e58d6f13889615a4e80fa32b8470f0bc6fcfee20a1425d3e2641e9229b9ea4478e74f1842e" },
                { "ca", "afd7b74ae3c9836926d75ff3dd30e6b5e647cc61ddf5017a07a7cb5b1bc55b43fa89558b95633274ae1c88f11227f3d668ab219febb51b74d39c170e04bddaa9" },
                { "cak", "e978ddd8ac806d3729bb77bb789f96dee799d3c10e5250a883b79d84b76c40a1184cbdb79b96aea83bdaa7b54eeb84674f65b0834de6de58413ca9c02381b003" },
                { "cs", "f62f93bdc8388dbd11824e6287a9925c3559b3fb7a66619fd643d3ecb5badc9e47e9e8b749c9b015ab567bcecc574589cbca4d8cd273ace2862de8976baae637" },
                { "cy", "2f0e15fddb50215c13cd02b6c175321ef4664f6d57ef9a18adeeeb16b6a37ab58328338932def57cc90c8d20c12e7644456b2fe0505d288a723d2b5397226301" },
                { "da", "38d8b50661753c2a67a099f6de943eb8066b12af4cefb6e96ac3df1c16a30e9b4ce30200de4d418d870d4dfecf45711d4f39d1595f7570463b16e69eb7df4f86" },
                { "de", "164c5fa1cdec3e8bbb450672599ee005b6c7e629cc3dfa20a0e913f4facc3383260f4af78f91d99c9802c974179df0985033814cb8aa0b7a86fd148eea66b9a2" },
                { "dsb", "121d2955cbfd131c4d4625de32099677908beec68b11a562fab7b9b476fa7b26f704962d67b28181ee4713b3e82398e3bc229bbaea8cc11305890096b0dc6496" },
                { "el", "3350d5d927215a9c8c7faffc7828be6abdb3e5d4840cfadd7ab7058b693dba8dbcb860b7e3706a7caac35b12411c428d75a99a7e53a7bc79035369b2eaed7d56" },
                { "en-CA", "de88d552532845caee4ffaf03410841a7da4cac49fc2df862d8bcd09b5cae6055053f2db9a52b51299533921f4a1a4309f2b7cfc7ee6cbc1b8157ef600c6bd91" },
                { "en-GB", "2c9fa9e09fded13953da3d8be71629e300b47b629b54da0d722a090d807a3becbafdd80619bbbc66a7b107ed21a3f1e9d0d8d61daf40d7c2caf68d5f244c3913" },
                { "en-US", "2dc603dbd1871d3ee198c105c07439af54a10a5dddfcf24e0abd092c18adb7a6030f1f0b51e5c4730e7697bfe49fad07785c052a1dcf6d4dd896d19645a2f59a" },
                { "es-AR", "f1eba2c8994beda48a1c4ae2cdc773441da20b2ea8c3c6769d942381879515d73aeb77d7c6c3160544f5c9155d1e65972ef491a15c43b3587df540c318db5ed0" },
                { "es-ES", "57fd47be286ba2fb57fa464d308cd05847b323ff6a2e5248a16ca02a5f331b0c973e9fa2e2ab6a2e883978b5f9cbdd8c90c455cd1cc8268dbcde9184dc37a203" },
                { "es-MX", "96f0f17cc9f76112b7695c5e170ae50e33e2fc1aa14217a90c617b6a7e71928748eb40a457b3df497e5c304654f90f1244247ba89adb64c46d14f693079ea17e" },
                { "et", "c535f0d50e70932387ea5d79d751d3019f97eb9929b63f3915a38e53568220abc256d2e4eff265d696a2d28271a9f93662256b6ccd2f673de9c5f62bf14a47a4" },
                { "eu", "3dedaba7af2eb8b172be2578c67d09ae005a194fefde26cfef9f4f3473ce11d7683ccffc5647fe07220292e261261ccd00ccd3347774492579cf2efc35e9f44e" },
                { "fi", "613b5abd1b736b485a0908703e5371083737e637b20092b7b341ecb916ee01900b803f9664d88c26679d88241d66d6b72dea893f874655857f84c98e6518faf6" },
                { "fr", "21cfada6257f7c98175964994018010c5cb70ec1e17cf3a9c305b846f75c642634e9a48ffa89d7e55e25b8c159cf019c6df4352dd078913d5f2bc43792ef90c3" },
                { "fy-NL", "01fd39c4707c8c248d1fcd57bccc6be7c609eb6be9dea2dd5f6be0d6ce37c4d5108f94b2230b56ba630347b5f97aa009141db8ac02cee922e1ad2adcc2503011" },
                { "ga-IE", "a6332a5a1f1419e365b42159aaf6ac94e61071dde5958532b57d2f3aefb3f219c28a13c08d2d6e8bb61c75473dcb5fec68a1d5be59be2e7ee2b50cb208fc1885" },
                { "gd", "6fa5678744bab39225d3b5e8dab9a1fcab9ba61c03b59e3163f37b3a76202b9b719a0c09500e5db1f0fcd6cae18b917cf33d79304bef638710c6066413b40819" },
                { "gl", "80fd7e07930c6572eba404ac7eb539d3f2035a23d00dc827710affcc95da62cbfa13b2d3f03b4ef583c2c1b13b8f29a03850a91cf2f5c15414b1c66d2c987e42" },
                { "he", "476a74e2179ffafc7104de85823cadf31892d52fad20d5c3ae1652344078aad238a6be801e6e9d3916b5f70ce5e02862495896fb4df0bccf9e9e8d64e8b0b578" },
                { "hr", "7a51c8917732706cacbd61c39a7bc8af47b5ea64fd3e532a83fc12d3e4b383b64d27f96c6ed640028514ade3b5afe84da7c1c6fe6f2b4628f7e442252cf6920f" },
                { "hsb", "9400b6bbad3cb6804db515d00677cd25c229b286879fbdeeb0c5b8567fe98b3fe047f2d5c9db2d887327624e29a2cdd4571d7cb706505811225d02ec4d07aa2c" },
                { "hu", "203c089b23e83579a257ad8091ef89cfe8401c99c0ef1e4eb3dca14a28b8d2e932708e14d3709d7032edccc619d02dfa631ea5c7341b2f2446b578c4b8c8a990" },
                { "hy-AM", "f3420d88d7578868a98259288692158580e4006b753e9739532de75b3ee89b02bc518312e7a2032cd65f7456efe37e0ff2f26797f12fcce8bfe62b6e83a53397" },
                { "id", "5b8d5a89eaae24ecf15660ca43ab236a71eb1cd21f874153ca6d941ec1f1c2bdcff3fbfb16ff0cc0705043bd0493bb9d8180c459c280b5e46bf0f3f3537cfc24" },
                { "is", "dadd29e29738b8dca5daaa038feee919322352c29517ac0ad57f8701d37a1362f16df2eca19367a207f62c2838926fe153020e535649c78655e600aa6c8ab0d5" },
                { "it", "f8c7f1c9947b12ba7c7385a712d47bd9aa91088e1a9d108058c31d285a4b980eb5b06b7946439687fd19182d42c83e306986d0da801cc4b50182993bbb94cdc3" },
                { "ja", "436881c2a2465434bcbcdc6f08ad6ccd97529863c58afc64a21892df90e7d5e52d39782c7c0e194ff7c9da6164427a48a1bec682794021e1030e103c37059e94" },
                { "ka", "ba7a3aa3f9c32e165d57240acf13ab6a8e5176ba7c8ca2ac33fd8330e1f1655b79127bf3e84f96556bd2071ad13df9d63237564db8c44c720946f4cc580a5624" },
                { "kab", "e56e993b49b4f052f063a76eef6d38f69b3867f6fc4648cacede14ea4d3b86c3b7294f58db497a3acf21c5f41f80b1b48bde3c7823f3203112e15f36e1c7fdf8" },
                { "kk", "b6d394fa8b71dd7c3ab0e137f10b0c2c73addb91a4ead3da0e6994b82fa413bd8855ed42e9914b82ec80d15227ecbd31db98a4387aa994e7d6dc70b4563a862f" },
                { "ko", "0b71520d1599be4c017335824d2b70cd7b7ce5b9cd9d4cc42d139d2db3b6d53809626a43b9b7a35c494a48c95b224be3948b736bd2612df19917d9654ef561df" },
                { "lt", "89ac88ce9caa6447b9d241dc9b72d87cf9b383e33be37d726e9bbb610e8407b8c5436eeb8aee0dff5c5cd9f2fc32bbe1aacc7c75dfaa640b860b357ab74d6b9f" },
                { "lv", "52de8d32c116cb6f556dcf27460b1147cc26e1a8a40df54a28c492f6da05d72166f5241faf26b1c675d489657b69d2fb6a9aa66a020fa5dd410b209d02af1c3e" },
                { "ms", "1bc83dbb1e2e85bef415fb2a4c836e04c6349b9752e2276b425395f73c07101380ee55e64d41a6b4cdeb381b22c612d8047912aa8dca1707264c7b6912ded554" },
                { "nb-NO", "27b884141fe1ad417d785943f218a9130d39532d52677a581a181fe24d9411e113fb3b77592ee210235ffa2bd5e3c93b9bb59583405d67ffcf9e1df422556615" },
                { "nl", "42901b64f744f96237536a7277851c3241076ed0bcff841bde9bb828e2ecf89d2abe8b2140495882de9fc1aa5829cbac770770f93094e8c4d5787ee36df7abcb" },
                { "nn-NO", "9a1cf93ec596176923f5a47b5999668c7be5c6f5f37122b4fefd429d69a3346376f3aa42acc976bda17a802578c71d5a058e9f1421a91ef0753fc806e1342e81" },
                { "pa-IN", "8c3764cf4b5c0165c1ad3cf29db0d36e9d418bc6f60f4902c5b262a432cb9eca554e2da3180516ed0695077af5c2143a57a2b5c246947382161f42a6134aec80" },
                { "pl", "1f44484254167467073cf6d2538a904f9ceca6a8f32115a54e33701b714531ef51d906dc96d4009c55f692c93f971f4b585a8bd1b46dc92b002525bf182d1422" },
                { "pt-BR", "a6986fa016eb3f253c9bf02a51c29cbb4ebd4afba9a50813a99648e6e500d0994ff55e63e917008c68efdc0da730c78db6b88ab60c80e0a64e6c726301a6100e" },
                { "pt-PT", "4cdf8833eb2434438b5a497d207da5dfa2e84de3675252e9940f2c8a0465ae28a88abaee56a06aa091485a3e37062f8e33cf9989ea326dad5b8d0373afd6f9d6" },
                { "rm", "f897422366d1c2a3a5e706e0c6353a2839b7716bd9f408128528bb658fccd48fee88c02693eb58237450833eea6569c4c9b4dc35accea788e3317fc997f91336" },
                { "ro", "03fc2680827a9acbb92508648b21089ac15f6be644dcdef2893bc1a8c61d14f29599f167292ff9a4492164bd8dd0fe105f0017254d80f1497dce34460f212ddb" },
                { "ru", "c64c2560d3a2611db567c7731f3a0dc04992728259b0b2a8b6e3022f2edb7c304fb6afbcc5e44b17125e77dda55ace292ca10ce31f709cc07bc5df6f3d83e238" },
                { "sk", "06022648996c7001d549b1c5b23e41b986595c6c604fb13a3862cb366a13df8297e8bc5670c667d07e92b9eeb4c3d8e65474a64f1f717d080824fbc9f0cbd51f" },
                { "sl", "b34e5dcbb168ce1408fc813be91d360bb3b402b446ed1acc601eebbce2f8b03d8f37f62ecead2da7fa17998ae6d86cdb7e9a10c5c5c271cacb44e71c56c41685" },
                { "sq", "86fa328c8577f667a15f27deaa90e05147806eb5650d27465eafd28a7da889106d0acd98036914137c623275f18b7395d84193bff6d4c4f5f4f9ee0ab32e17a9" },
                { "sr", "51a455a9e0bdbd243bc089a9261421accedee9573dea6b75a6cf5fbaeef540013575e0a61ec9e5ada0c141d0d60b00dfd6a85c352e3c2b0b59fa775094c63c4b" },
                { "sv-SE", "faa160242e9f8602ab7f0091b221813de989ea9badd8b9be94dc8625849bb259dbebfbf428f6f10e7877ca38b8aaae8b8eb407dc318dfe0939f595a0e888c8e0" },
                { "th", "79de45959e487f577ccd1703278c39594e618cdfba02efc78ad8415a83e102ad196ec7e8e0f27c610b247a76671ef33651e83f51dc18adb4013b5f9c4e191924" },
                { "tr", "0ab2e1f4344705a93ec0fd094b01611e02ac5927893b41f92d635218e7bfd43164aa0c0c65dd75ad920e36a3f7122ea233369392b7480fd8b7d9b0336025fc94" },
                { "uk", "71d3801795ffbe63f7931fc64b6afc1ab0666df18c5ff0ec22810c62cd0899592314905236d1856b958571a2f8175e813a0911c14b084ba6cb9f1ab3aed7acb6" },
                { "uz", "00d7153784708d4d997e2c6b3530d296746175d099b20d6482741d65601495a0faa4d76200819b1ddbceb657a3a1a2fbe1124ddbf06e040460bdc454ba97d447" },
                { "vi", "617befdcdfe389bbed98306c8c7be3879fe7150af3b8317c73599276041d9e95b2615ed3903f39a1655c8ba05ac696e673902f9233c854940d5b00b8190bf0ec" },
                { "zh-CN", "f7c3c6957d9b9cdbc8066293941d016d64a9cd9e3d1b44d6f6734715e761b3eaeb5ddcba88baa594a46792a461680261bb448dc270387a5baab7284b9562943d" },
                { "zh-TW", "8c8a1c57ed5f7cda4dbaf1f95e7c82d2950a1f1fdf43435be3e50008236dd4cc0843ab5a2782154cf97861cf9a766b5ff646e61c1d8ddade7dfde031a448b2a9" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.3.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "8465d3d23cde5c35b2b5171ac83766302a2bbf167d0819743fe205276fb66713eb9ad176bbc57aaf3044f2ebb9d8a629d1677d373cacc35cef596319f424b130" },
                { "ar", "0e49440796e913d798d3e5ea798949ea47dc87ea1d05e3e8c7a35e75d9569a584a858ca67396c49d68f644e6d22f06f8616324579b35c6af8f8fa97b903c9d57" },
                { "ast", "02cef10731bddc6df4789a3f3754ab1410c3974a10ce8c43ce15f612664c111d1221167e701cb54cae1936e050370060193dbff57287a9425c05a7c8705eec9f" },
                { "be", "4224d2f3be48487f5f176cf151b228a56ffeed53ab5ada4016ae30c4150181f7f4928bed8242e05d582fc426b81a287e2cd55aa27d13e39653370345e6b0be23" },
                { "bg", "7715d71f178debe6bbef639abb86d8eb37803e170bd1f7604c4c025eb7f6602a677376254007593807a2ca2e3de56a1a703aa179205bf00a23b1281efc869bf5" },
                { "br", "9970bcdefc689cdfcd136997e0a3fa91061ce0aaa08afd5ca4e94d4b80b4459f7326453dc4a3f78858fbe021b61b441ed071158aa8ec76ce7a3d2eec86abfecd" },
                { "ca", "c97882fe293610146014f0b9835638e0669ed8a5ba356628ca1501f1afc3763000bad589c4de6efc4403181e23760c78a7e6a968bdc2c268fa97c432192cc1ae" },
                { "cak", "6bdbc9394052b4659f7c84ea72a6d71592f20a3367e7ed4e98e2305419303c40ce5404d1bf3fafbf21a80a3c7705f6ab0a4f71e23a08e22c97d9428c4299aad5" },
                { "cs", "797141c5e8980201c08e4e6f803328b111f854478d6b3934f6179d8e9707cd197c4c2668b47623cc2180adc24ffa523ab24db83ee73d39d46e45faabfbeb76db" },
                { "cy", "329c1e5fb144fa123c259246d79d85d7841600a2d761208844c1df874e7bec45605ee768f66030455c291e101f4e80a4ed5a5c33523bab7e6f67f9aa9cb210c7" },
                { "da", "56bc987875a89389c6d467cd694ffee3be6e0be5c50f3b606ec8a97d5840e962a50f2bd79f4eedece19a7f0fd3eecfa310a92e6f9aa362251d8a0ece8c9306bc" },
                { "de", "23e1766c69a9b54e84aab8e6e92ebd779baf9ee432d371ab9b587d7f6124f706af795c93677659adab26769aa2bcf1faefd727c0c16d5f5122622964ee1d4352" },
                { "dsb", "4749290b11f64a1e21ed8ee6219234c08dac4dad17e0c796fe22ee18e46559b5a18a9e521a487a3457e15e593bcaf979819e007f2bd50a1752f7f4f0f11d4b8b" },
                { "el", "a12673aec88d9f2336ae7e01cbcf153c3e2290a393610ffef391e3a5f2a022804af4cdb03ea8a89c3896dcf960e538e5cd5751369b193639e7a617378e76b924" },
                { "en-CA", "c2fddd76fa508b6bd5dcfc26cae486cf297dcc21b3e21351a7c111be64cd3241db3840436d7f1eda15b098a435e9ad876bf5efa44103cb6f33a91cafd6117513" },
                { "en-GB", "e0d91ca9e02015a49df5a76b4a4a7e88b6b8ea348483fdfc84b5b18ba23164a9b2765bab12f263ce64c8c01ca7d6f467144da571fb19f134282c6714fe4a8e9f" },
                { "en-US", "da4bcc23b556c38390b4f723604e8346b891a1b4605fea43eea48c7991845c52b96761bdee6d85f4bb1062ec3b6398d1924fcd2c701dbfe795f912199b160ada" },
                { "es-AR", "81f5c2957e4ec65360b8c6e7b9a8c207032214fbf2a0d69ebd5996e7a52f1c794d773f2bf89fdd376b5280020723235e5329b8b0f138f7927e23d4b49bfd66eb" },
                { "es-ES", "645d45ec1b8291cc0d690a13a4a831f0117454e7408404bb9df7e5d6374cc924ddc1246d4cb48b68330987804b64c75cb88f2e11a9a1c887ccdd6d3f9c46a872" },
                { "es-MX", "40a8e69c3cfe3479068d5ea09228a5c9e257c42dd65021fb7311f0376668ad819f4a9ac313314e73dce68c0fc0a23ffdc8db07f4ced158bff88915247e78efa9" },
                { "et", "34f0304a200474948381bfc2dae58463d5a1546ed0f958ed477d89b3825669efbc5c2af086393137de51e2ad9a69ac1b3a720b1494f7a3fb618acbcd249a6810" },
                { "eu", "350ecf4667cb08859dc46768c236bbd53b504a32e39eb5060368a4c64c5d380e141854af4b35df10fb0f8afdd2d3aed771506dfb540e1e770af8cc62473ebb93" },
                { "fi", "aabda9b95b60eae014295d500589102cef9d1347e57fb2000f78da4b22611d0ad42f1a4aba17832296839eaecd3b6b18f0a0f698cd2c92b7eaa770a19d525dde" },
                { "fr", "466bfc4c4d7e138457e4d57f1a5eda3aaf15177e35a7baa57911e4443611f76a55319ab3b4e6eae0165a576aae8e42c282650eea8d0fa19a5b8d868f2b097e4a" },
                { "fy-NL", "6f63164947db893b671796c9b1a8a5939675d89f063ba13ecc0d96e135a440bdce536c6349f1ce7523c73e82127ecc6fb95c909474b23b292d49283b8de50966" },
                { "ga-IE", "2822a4ff242b727c9444a841ceb85ab38caf731a1cb460b8852df10e9a0634f64d7ab337f960a75f787439f5c5b6f050f057962d91b4e145ca57efbe728c4094" },
                { "gd", "47596f532c784306e2ca12a1c0590c173c2e967e01a747e7f04a594a17ee24200c84eef28b38e32933aff25fe409e97ffb990ce53c529efc18e2685428ad90b7" },
                { "gl", "fb2e245ff2702928dd6874b26ee842a8992b932f62de7b30b730a71ca7bd14e40dea762a3838a7912e24960b7b9b431c54045339fc4f5b9000d24eb04b7ea5dd" },
                { "he", "e0011e2ce3e4d7423d804fe9a82be53202d7e0f8f0b1c5378d28ed5c83fccb6b181b87fee6860c7c32769013a4d1e7b53533cbdd3c6a0aa6252fbcd385e2c772" },
                { "hr", "6724756a068bb6980ac4a71239f07c130b9748624723f3b32425560f39c73c4df8a86e0cfaf74cf643d8bf62713b1491330589d7590910ec64733833e1d08ff8" },
                { "hsb", "a5c8284d1456a2935f816e96e481703727ecb91930dd8e553e2b9bd798580387313f7e975a3e070db9c04259ef7f4bbd434b474ce8fe4ff2d77e8e7cc40b40aa" },
                { "hu", "9d9aecf08915f026368997058d66fd1f7782dcb6eed6068acfc8c775286ac00aad6159d2439a527fdfc939d1ee9d1f6d6cd17f178ad1858dea6cebcab80c6e55" },
                { "hy-AM", "62293a37583a45c2a1f7af78bdede8df2b82ced582b6650c6d94e717b762b7792d2851a48b96f61a98e74b2ab6453687623d3df3bb9fba5966390b008621d8de" },
                { "id", "f80e98c12215334d437d8c50dde2482e8ff4e3ad9069ee216363ed64732b37d2fe7b87d57477527f0b9c511caadec29921dd089a6e1ab4d0224b2b08334d20df" },
                { "is", "81ac1c440aeffea091f8f35c88bb334576c4ae4a1218ee2f5ea129706303f0a1af4e6272b3b819b24dda563591dd0dd1997d26d038466cca6a44aa6dd29160ef" },
                { "it", "6797d131da8d7f68f5671ed2d392ec03781cd4920c8555b4e889661881a16de37697f613d9c7a3cd1ba3e2748a3ca9f16d2a83c1b580555211bd775ee98fa9df" },
                { "ja", "80e4e0c9a2f52cda1dab4e6a712295b5124687e9d5e7bc06f1d0a701359608fa30f0ac0b60fce093c5b10a22d237347a46e1a34332ccb2c38caf4177f2a5d2b3" },
                { "ka", "0e2238f43ec0a37d91ed4ec12c16cc740f19cefbe3c2f8afa40225983763501b7fe3be8b4ecc14b70f9c3e845d850c7e5f4b916dcee13a78062ed74d85494321" },
                { "kab", "89003789d2e1d25803f1d030a42a9f10fcc90f4792fba19d60ceda42fa997733c361d6957893b89a35c07ef041f7fb331da2504e7b25219dda1b2463e1c7ab14" },
                { "kk", "c16e29b7f7c6fcab8806badfa09d298dc68901a73dff7aac846d6f5f2a8f52177b020b8e7c93d4efda43aa801fae840bd8f319004e26270f833c483229206ed3" },
                { "ko", "441df62440c1bee1b3dab645706d760697188c88465069ef28dd9d89f08452492b9f27159d39e2469bbb90f956f217b09a097940886b532b1a5201ace3cdf024" },
                { "lt", "cbb04f41bffaeaa47447e8d58389ea18675cc88e38626d8793351625687cf2e97f44cdf5c4813fa13ae8991fbe88aa12159276403769153eb71cfd8f224345ca" },
                { "lv", "06f7279e67116d9b74d05f1f23f845da9304cf866ce9c98111a8387be400ccc33dfa39a5400818ebecf00d837fbd9d62e55d01234c6451ae60a6abeaf2c5cf8e" },
                { "ms", "d50c2bef406e4a47659b85842ee8219dd92d92b3dc0403fc9ce8834e827f54bf4d0ce876182312b7cbcf9f52db922db50ae2644bb771b387232c5fc3f260cc30" },
                { "nb-NO", "f2cdfd5973552169b68eb017c887e6042d39886d6ec05dbefeae08fd1b7df5b3a7a108050d25d8c03b752c18040aa13b7afa59bccd7513305d24cf3b04c794bc" },
                { "nl", "7b2aea870bc9d31915e21a04ee19202f19e6d5f8c26f8acc5c586c082f83211ece7a132c3f079788a17f0fb9cc0ce8514e15cb76b5657a329834ff98eaf395ba" },
                { "nn-NO", "e769a760bff8e78621a63a2165444b1bdfc5aaa46d01080415e0106b17f4d6d5579bdfdc8d41c3235cf1d5a414e40f886b14ba12761595edb398eedd82435d8e" },
                { "pa-IN", "9a0c935962b003eebfa3ce9942ab989b07f40933a3bc94e661c8c9e98e67ec6b04685376771dc518c9df67821a01b9458fc46674134526b07a6dd2dc744c87fe" },
                { "pl", "280d5b595f16a73823f0552a150c6e6151a86bf926f5e8e70fb539a133cf6213efc1a85d766711e9e938e9d78d274ef6ae6a4f46b70d5eba2bc0ed2c6e9612bb" },
                { "pt-BR", "1b93900fb2c74510f01fc6c2eca8f3e4ec5e69c3ecc1a37b15c0568435dde27c01dd816ae27bf8041714a7254e1d41c9f3cb097e0bd931a3e6e8392225d56c24" },
                { "pt-PT", "7d36868e359ed6ad9bb46a86ab258b96e362fa886e22fed110648a0d1b06f95aac9d52783a25e4c9b54b119f4836ee405de235b52844bce96a77986569cd6a27" },
                { "rm", "b7b220a461baae2a887186a88d196cdadf1b3316c04983ebf7bbac88657454bc4841a75ff3fc07204bd28293e8896d14ce836e8c2f651419dce9399a095f3cb0" },
                { "ro", "738c6ccea6bafc574aa16375c0d477f21821dc564fcc2d54397206c282883db78f44db3a4f831893df68079f7ddfd268fecb1c900c858ef766d5759602add4a1" },
                { "ru", "829242404a976d01199856d27a9516421888f310d5413374c6bf6ddead6d87a4c1bbec397ba9f3b8307f293bd24c1ef596cfbf2198f256f00c8cf97ba748a645" },
                { "sk", "7d4e0fea012cfdc433cbe1b9b57958420ceed145ff6a4b33da9432f26df095c332b409d549735c7e1a255404c88f31e1899151eefff5fd17e458551aebe8d862" },
                { "sl", "3a87915366aec2b1f604e375054ca2fe2edd7063998658f8a9e3040f4f790c75d7e8c401ccc5f648c262a4c7e05c4b2a3e91bb7f3e78909780f7747c62a952dc" },
                { "sq", "e4de0fcb9869304dcbe4368d5c9038a0b224c3d9e7fe1aeeccdd5c6872a97197e2e8d09c51ac4413aac8e3d8929f574c7347fa2b85b5c98b2d0b6fc4a38c6080" },
                { "sr", "43fcbb5c217c7025614026f1353728d4625e7231f6c77ae2e07a84807bf01189a22dc4bc4dbf9e890b8b60523ba4ba5b700e292c979fc46a3ac63f4c7785b768" },
                { "sv-SE", "181be7738e02888df566e703051140ef5be8b4c35bb06ac3ddc271cb825db4008bea32dcb4b956029fecd42b31b908cb73009668b936cdbd6287621ff0573380" },
                { "th", "a416c7a16456802803ce87d9e066cd1a21a3130f7b815cf5038c58599fa8980e65992700d382efae895869c7bf2f56538b0b2553a97b6bdf613b39bb8ad6f8f6" },
                { "tr", "563f96f703149dcdfa8ebbcfd155820f4ee2a5bdbc5c3a94fb861d135b2d45d2fd8f7031cc47b35c0fcfe14152a060fa2e6dee83d015dcc2deebbb8e02a9eaa2" },
                { "uk", "6b1c92de278aa952a5de2f7e316690bae7745ff5387fa29dbb83a5ab3417eba96ef02eb0c9d8f7d5037842da840bc55c918705cc4f88793c0723f3ccb2a844da" },
                { "uz", "c2a4bd767131101b651ca12b8382cdf3c70af0e7319592e5c3c69fce4f7bf81f590a4284adfb25693a530096fa04966d5efeb129ea84523b2621e3dee5457fe6" },
                { "vi", "25a4f3fe29f1c9f952c905460541b591d2d8fa9de8db9d2e82f7acd3c551fa7966722907d275a49ba8010f6974fbffca9d35a1a6953f812352e53a0bd04d55cd" },
                { "zh-CN", "540433afd116b1457b041c0567612f8ad22dfac55af2208ddcb27ac9aa76f5a76893cfd7521a978c218857aeff9fbb4534f85456eefccbb397aa86424e3818c1" },
                { "zh-TW", "e480ad120da04b68af4440df0b3b73e6d21d367f506cfe407582e8118f441d4f0657efb0771fc1e57cba9f676b4e58d89175ad23f00275c3849496b8662c3a0a" }
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
            const string version = "102.3.1";
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
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
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
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
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
