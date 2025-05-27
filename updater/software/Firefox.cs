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
            // https://ftp.mozilla.org/pub/firefox/releases/139.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a80e417c090f1a0afc0fc1a1a4ec81c147bd81642f14fd3d7abf7ce5b20df5b19e0ad75c56c62f39080208484adbd580feacdd6f9b5070e4796fcad5e72321a3" },
                { "af", "2304866b95618601d96d1f8f5a9d675e82fcb8e46e44f6d20259a2c586e5ab53455ef29f0d752081b01aff595fa99f603b06ffd6211c688465b155bea7ce456c" },
                { "an", "f8098c0d6db193a928477bc21a25c9b9089a749db8a5204c8d24a3a264ad07c0d23fc85f016b2505519b6442c7bee1cdb3f3e2b3f1bc4f6787849fb7eff13102" },
                { "ar", "6e876c4cbefecad9f31352cab2dfff28e0049c6586fd57a73dd3ce412b7f470a81c9521fde77f255f89d6aabf182c8ac0ccfcb2e77bc415bcc24c9127239aea3" },
                { "ast", "b3202f1d163d924da7e2545086249c1d33bbd68d00d7936211c2eb993299462a17013403c01eed45b2b41615f9a1163cf6d0f48cfabd93011f60dac0e11f2ad3" },
                { "az", "b2cef493df95388b9f7ab92435f639ad79be6eaabc8ef2c55653f9360aae4a70372867c2410e975fccb2ae88a7154c7d54c235fe4bd0fc5e79e6801eca6e692d" },
                { "be", "e7a3978886ba741761526186b4c9435f7bfb93d016d77a94e1c4ee9fa0d5526127a20e4e37e31ff074c68ca3b51eacd1daf325287d5104b8f687bcf27cb013f9" },
                { "bg", "5ba72f07aa5c495d7e86a43ac94ba1daa549f5f12a8c5ea6dfb833345be2ecdd684539d8db4cca2fdcc642d2c0c8cbd26fc45ceee38366769e4854120462bb73" },
                { "bn", "b41b34c1dae88ad690a5299490446b3b01f2b072da15a855ee87e90230ee2ff493de1eae043e2939d50764fbbc8b72ad6b259cbeb48fcf82c660b6cd3a84f59e" },
                { "br", "b17afae0c05577fddef2883cd16acfde3899bf2f298abd0309c2daae34f7eab60f60d252e02deeb347c5269910a3c6d39a4ba9d5a1e9c10e4f97e78606e48279" },
                { "bs", "7eac83419ae9e1c7fc548598b6f504e255dfac18a112cb1a5a4240bc7549742b5d24dbb341397f2495e2e2306b15b5a59f0136e6b44a870b9217df9873db1a0d" },
                { "ca", "e56831e7315a1b6c04ea99f7ae0b87db6e0a4fe02b200c87dd7a4cc5bc47bc2e5339f2cfe8b43d5e5b24250285b30c2ee8c02b23349771e9abb31c5551bb9a70" },
                { "cak", "827002baf4d43437fa1ef0beb012ff154bd6f46b10c85a840aaa4a9b770613f07a7130900f461b36da4127737c17e9240a21c9ef1c06c026e698a0b1f172d314" },
                { "cs", "a3b0ab66b431e45137e186dbe3128aca1b14abe927dabb21d70ecda4da233d481cb2c94e8845f4be69d430cae5f5306d5cd48a16a3d95559e34c54d8a9e5c6c3" },
                { "cy", "95fb401ac35972f4931706ef08e261800c72cb5385ed9b1e7a9014588e0a2e6dfe1385bd7d2a77ffeb61d5faf294955893486a6b37a8c8232740ea19a7195865" },
                { "da", "f59d81c4aecc918b92940d58e2ee807d1b5bab73c5df0f9e47ead2a34e920c2f9c7a06d31620df4da52002d696af50bf38deb4f42cff8235db81ab15aaf73f4d" },
                { "de", "a9d54aac8064233119d1a2303a8c2aff79404a3cf31de7ce3d9a686b4abebd0ea5d1b8d8aadba56aefb4fc0d2cc60512f4035976c05a227e7564972fceeb0a10" },
                { "dsb", "580328d2244004c7beac0b30660d43bd41c6c840cc7b0e246b12aaa9780dcf51cc2a1398f10d53f7ee8f0ea44407dd0d69281cbdee5808016f997d8097f8547d" },
                { "el", "ab4ac21196b5f089e0e273d40d78c90a6531a92f33073622864c356088cdc776962919aad9b3142eee36d9607bddfd0b380a3e83b1c02f29c60742a215b76ca1" },
                { "en-CA", "95f317c22efe54a79df776add7c981a20a7dd4d4954cf76fbe9611068e5fae8eedf09553023d27df85a1549d8a298c4386831446ed916d13b542a199263b9990" },
                { "en-GB", "0a0e26edb45adade1ff83b2d1bfd85f98fc906e7dd581fd42922b0cc7c4da43e474fd16adcfa79b0f0e60104a49009cfcb751c796aee9b2fc28bd9eef1c7715b" },
                { "en-US", "b2c235831640225608d7737b0d53b759b7671222e2570630fd746293c7eca485b86d72374f2326b9282c82480e00254d6c2350b8261586f7827f630ba9f5d7e6" },
                { "eo", "c9c2e6d0367b14ab755c190ccffefd0630d37bf7980ada7f5a733b71ddf7ee0b840ac97563d9d68f808273759003e2845c1f53a0389e04dfd56d43ba34773dd7" },
                { "es-AR", "fa91ca5c3d1e8a37b2f9f3de29e292ec67b91d89ba254e42541d3ce60a32c69e7bf2ed2982bee8611d622d1c2d882fbfc717225f68c6061e2c24b0eb785ffc76" },
                { "es-CL", "260c68f40764c9e896fdacd76e67dd0b088e6c3c93ad242c13e2e8c2dd245fa3a33cea5375dcd30f114f73db47c1d77b0cb078966ee8757c4f509696cfbde97d" },
                { "es-ES", "3f57ea8552a3065fb159fc6d492d7b7571e82cbd4e0b773dd549240460996628a98f77f699fd3ff690be5e690a874eafb2e55b6a841048f11f5eea1fd282693d" },
                { "es-MX", "a162623d5653b81085c9f94860449d3d9c3a624bddf77398dee4e546ed5420021d14cbb6e04abede4cdd81689cf8688d5622582350a298a0ece74007115d36c3" },
                { "et", "56055f4c9ee81dd772063b0c18daf995d6e38085e71010291b5a1b5870d85c03490bc53c5420839b19b9e73a9ce604a6db02a314f4047aa9d65f2b6c05059936" },
                { "eu", "e9fdbf0f1ed8619f37abf55d81c9fd85017b727dba729c69a77d36e3e5c4cb8f34e919a0abb6519ca06cd43be4c78f15674670c66c8cfdadcf8a33bb7ca5b663" },
                { "fa", "24d9f43b1a1b3eca2f95ec8910a97eb4e9212f2d1f3ece447719157b5ddc190e45f8567160f8a3d22b9214693d927974cecc7afca01f5ffca83d0b84b078dd1c" },
                { "ff", "56c6162f94b40dd353161f5eae28ea455f0db23640af2831b99eb77e502a68af116f342e1c78e7867e263a6df79048d10d390f8b5811f3c2cbfeff40e349341c" },
                { "fi", "aa6f997182537e42019415a8932348b7b9a59d6e319768f7b96e0eeabbede797618674f83281ca79921cf6af592cec4a67055cd098bf9cc915e147634d158121" },
                { "fr", "afb99c500cc4052069e835e90b2ef99f5a5b6886c4408cc7ab9922849826360c9b3b279c4f8858ecf6f6e60656acff93ddf87f92bcf1b3196d1aa7f82c91e8cb" },
                { "fur", "eac1a8c2e3f2dac58eb6e6b46d891320a3c6749779f8b3f0941bce8f29ded1ab5f01850bba63dbfe6ba390602396e2ea9e23044ea69601e9dd34ad3c3ec4f244" },
                { "fy-NL", "5bf29aef80e663482d2693f7250b74bc42f50ce76f51ad9b1e1575a6438174a23db53d5942d3d3145eae7f3e732419c1978ee0260beafb06b7a45c7fc4c09c5c" },
                { "ga-IE", "b67ec25ce65c6f138843bb934da094f22d07025a2c5bd35cc6a955b96dd30728fe2c3069d392cd35915e20d5bb1beec5095186fab9dae92ec2b0148f91fd371c" },
                { "gd", "32db14f470fd52961983022a1588caa4e101bc99783ebd06d5df4e098cfbad8bf26ea30dfa0c4c0d18905a4ead3fdbf1e1b7e30824ba4e8b0f05605080b53bbb" },
                { "gl", "08f2dd96bf800f1d5d9694de5b1de3b8021e782ddf4ad4e49b815e32c8d907023b30b4bea5b6e267b4ee6297f82c6418f176960c25a455078cfe105d5c5868ea" },
                { "gn", "d35648d652a22fcc2d871c17c114ee49f6dec7fd163862b3ee27c2742948a9868a07d31a8753654e45c3d3636b688fd6993b17e9b6aa46090cb9096ee3bd750d" },
                { "gu-IN", "2cc3b5fa8d1918b0f789f53a380befb30d35137f462beec76457ec4fe306f30e4178856f25e1be835095037c01cfe662dcc45995f36d2786ea32806c7cd54bed" },
                { "he", "40e32d76868d039cf45eeda0c723bab261a31578f5e2c0e6a4d70d47b17c75bc8b25d92a5e2be675cf9cb45f9fb930bdb2064a9bf71eecc4b77b992b5a6ca881" },
                { "hi-IN", "d7b7c8f1e2a5eef6303d7cbdab0a5e0348ddc9a45beeb8888f68afc7fd660e97f8bd1b1c5dfd47bec462a6feeccfbfd476ab32a056b081ee44268e79ea114b2c" },
                { "hr", "5228226ec209a7c74612aa951d70354fdb50cf4d94761e2a99c9994a1d187b46e220a0d487acf53f625ac249546df15be9d0a48cc09599065aa22194e2d5a028" },
                { "hsb", "a13c8c6b6453830c2eaf40f47f14735afb7e747c442b0e77a528414e03c302122c6429e8e512039bf56a17635a7f4c1ab1754ae95b745cc827ca787ca6d5d451" },
                { "hu", "e3b133560ec209a062598406b3b9cb0a88ac1bd0fdffd0eb38de0358bf79c49c2c50a586b1a635b8163e911df575e96f345b9ef8531ebd7ddd8c278073037c1f" },
                { "hy-AM", "e6d06213e02405df66078d2bf86ecca639ea84e449e5a6823077614b822bb6c582ada8cdcfc051d9a41455e933e7acca0c164f6743fffddfae892a6137ec4702" },
                { "ia", "f3dfbf2578f57dbf16ad4910f5d6e2377bdb93fd2a5d2b78e9d2230a97f0a3f0616502f88c12d24b5b57b3d57cff2c6447c568cf560989870227cd00f9ebddfb" },
                { "id", "f127bfe6f6edef61c26f46569900f9a728968b501dc071b8b20e8b85286797a69761c23507d7b9a80d7ecd5c00cc42eb2700aa6f1310c7660876676fbfd3d207" },
                { "is", "7cd7286cf882b5c707f8fcc55cf9c72e89b5495d39f2612438cc478e90ac6a0d1b3740422a126bde4909fc3e54c6f3038155f65735a034adc32feea9d41f96e5" },
                { "it", "1528a4b4cd49ea57ceaab5b284ad59c4f60e3da46caf2db974c45ac5c3bda572b4460f44a184468fc9e9c04f30c849f7785a9161507683813c455285fa223e49" },
                { "ja", "48ca01641b61ab17fe14535da6d18cf3f02ee0a5a701d28b1bb169e101c3b69d6d76034734bbcbe9f6c2b0c01046374518513ee069d8e0ac1f6b6b722aacfd14" },
                { "ka", "680a5a29b7148848a73743a65efd4fbf2b65e7301f0de8ec668f9820c0aac7c7cdd1d9598f961b347883fecf918d66009695ddacdc85bff3c17feb20da5e9516" },
                { "kab", "dc2a061527ba2fa37fd1d1b9826597e3d2694fe03fc8b6310640b8f1bfcad2163818804145d3a0a957e58ab6c738a1a43c6fd930635dd7ee53b12de975f49f83" },
                { "kk", "7dea4263a6308a832f23a9a843432ed6b6037ab771a591d7d94bc21f21e057b8797587785813c18c6056fbb1473af44e562169017597823b8a5bddbf94766ac5" },
                { "km", "f5ea35a7f0d2f3cfcf0a11583ff5999bbb4453970612dcda2690c8bc17491e713607d8080f2154d7f9ef083da8100f7c95e2c2eab81115dd5b5318f63f04cdb4" },
                { "kn", "f9cd119d61a23f53dc91a1bfefa1584ac090086d92635177d9a7afc706f3504f14b931ffc7d4591ff6ec5c11953b5cdd63a117cf451a402aade14d2ed8d6f4a7" },
                { "ko", "ae7a6bcd735b301098ec0673c8c2db830bfc3829d17b38860be4c83b157398bd4b4e1d00a36aaa664d055412a8b8db797b51736782fa5e90573afbbe6de77533" },
                { "lij", "027db93718e941280b9d6c63485578704daf084883ad9cbc1a81f4642a7118366833546736ff7081977d6605821c4b25c19a80468dd5d46f4a080af9187c5bb1" },
                { "lt", "bbbd1bef2affeadde02919ff189f260442dcb7542159e7d444dab2e7312c4d7a149ea18bf8938c44986ebdf5e45bbbc50ad621cc8edd4fa6017eef5b92544753" },
                { "lv", "f5afad0698ea7cd64024d78d0dfdfa2c7d7543d8f2c086507af483ddd4d3b766706db4ea82de59f86097d3f85ca72742b4885582dc6eb3356fe7216299f8ddcf" },
                { "mk", "529544844cc54c329ba0e8e1abbe8a9c328b05f580e45b175bc52bffe418f2100ed729b81312d0738811653f223b35fddaca8fd9c383aef46626880ce5414d5d" },
                { "mr", "c516bccabb6bcb1b5eb9fbacc380c0fa223afe0598694fe791af5f7161870aa03ff1207a182866e18c5cfbf7e32983189b03a3740f50f53b68cba6156c0503fc" },
                { "ms", "ad811ae60c97e0dea96f65cf055d21be639fcc7f2ee02bcbcfdaecc165d9dfac56154cd7865586d5c205986285e6e657092dfef7f379a5e5261a19cc7179dcf6" },
                { "my", "20cf245528f281aa4a93f784485f73f55d3c590955be306b8f501fd82a2f73c62ba193ba7efa0a0b0d9fe406b3b78d7ce6e733fa8246558f742304927b41424b" },
                { "nb-NO", "9d7d0482399f10f04e1ba59d90fdbbfae236852283b980d6b9d3c833bd30ff29f11757b5780de7a09bb690cb68ead594ce0c145c0571d7c3bdc20c00462be268" },
                { "ne-NP", "52c22d4ec97e4d218a93d4293eb5d7763a63fb434d73e9ea497e2af7a75f9d120844ee3fad0effa04ea5f0abc3817ce342b791bd6f2702a16aa5368d24252558" },
                { "nl", "769b62db4483692846480fe7c1d21e31f1123b0ffa793800f48aa485f672f7e18ebf16137bf78bb95396f472eb73d1882de50f00b4fc64e865c60bf37ead4ed7" },
                { "nn-NO", "53070ddeac0cb4a407b311057516c840af68e8907af235171f7551d36578326d9f8c3dfea1acf6b398c739e56f5a37f08b48de163e7e415922f7c45a1d3a2f0e" },
                { "oc", "22d4d7d55383b74418697ce28e3ed3c222a86cc5eb9108294404486c9b18460a7719d678ce5838ef3c0a9801ec56d91573f272dc84055b30b44e2e051c66421b" },
                { "pa-IN", "0623707b1b3e19d99dab412a7f847da48e9403c7355986396375c05e71a38609025635f9af1c23ea045825572c2402a7b358ba32323913855f08a351e4ba9e27" },
                { "pl", "a6be6397337e5d79172a63e12f2142bd143c9a3115f2ac5f29c11f96973482a451d180109cbc82d5a2f2456bc179f8ef89ba3ee6c684bc764ca64726ab24fa60" },
                { "pt-BR", "88d21f0e2ecf55501c1a7037a0d4de3ddb174c6fc4bfd63309f44ae6082ba852ac96123fb9084cb43f3c371fef2a3659b9e082ff3713909d6480f42a031f93e5" },
                { "pt-PT", "119c07f9f0649da5768f837dfda9987b9d2d13b52c7a502310f5276007778bebf5b5daea2997e2e1d655f88517b7d6bc28ef17ffa8da6d019c1999be77e38069" },
                { "rm", "6eb8107ad4b75770c01f316d73e4c33ca78716e62d03585b2321c708164cdc54d8f68a1eacd89db7ea77518f87f1fd5ea0f09eeca36837dd07f0871fdca58793" },
                { "ro", "ff6b101f4c88dfd378f6d69d6efd192d8a655101592e43d788ba50577b4680f829d427b2f498c8578defcad8c7c214e483eb38b22d7c3a98b6c66e4cddcde5e2" },
                { "ru", "b647db6b4e033f57a6e7f0494332030dd005a7831f62f3f0bace2bc3d3c44887c10fc9b2145ef734024356af0b1d00138e16add76f0a0917613a2ec8307ae520" },
                { "sat", "61f2d66a87638aaae2dd2c84f4e2e9b7f117b4c749fa1ba0635cbad8545a546d3b3d3621aa449c27739a60a0e435749c48a75d34a401c5d0d377343ca5f82558" },
                { "sc", "ed227cc4c3b94703358c64e8c194dc7fd9b5c814d231363b68077fe514b8ab978c35e3e3c1b6449c85fec3bdb0ff2bd411ae47edf84b8e547cb430bb6bb1f2ab" },
                { "sco", "48ab364380fa24a2a3a695ea8e06ce56d898f38c5d7866a117d0d327da13394b8341ae625024d9de422b6d8b94c80920274f711891720c74c3e7e87c8e30dbd8" },
                { "si", "bbb3964e28607285b8cd48e46b7085da23170597593593aedc9a4b960be11e15d7414eafdc3b4922b063c32a3f8ee7af449243828711884df732f655351b3171" },
                { "sk", "a159bfc71a86d1c97f1c14afa1eb0abe26fdebbec77a36fddc8621d8d6d1169a1d8f971e56ad35d6d0f809d3d710010bda4e3bbe7cf08a1e38319eff7bac8fad" },
                { "skr", "7bb9a9df5cf9de8d6ffc0e63612044c57c589914ade39491e893ef4f7432bab3c11132e31ed7dcfa9911c77af10a8a0df692fa577ccc4b58683f5a3945fa6e2e" },
                { "sl", "dcc991cad9ea2aaeaa5af5182eae977be646b63beaf88a854c4382a33c98cd71a9bf15b04984cda81f00d07ecad44bbea0fecf54a4d51eabdd71b0da0f6a0a9f" },
                { "son", "68679db74c32427c2f7ac749f741737953a9670338174b9ad8fa34099598cfcf3d1ba9c83153ce0e6081701ea2a6f55b2209e10c78df01522d9fd89e8121f422" },
                { "sq", "0818ba9a8e106cff90c2f792ba67c1881a06cf99ab748934b9b53aa086f6540e883ef39359927c3eac6222b02cec260140874ecf491b94bece06b0671b302bb3" },
                { "sr", "3f77b2c5f42c1ee1880ff75b202a8ffb577f17bffbef721dfd0dbc01c1506b46a2bfb28ff0e9839f7c09e6da0839799f116d804e435e06d4aed1718e67d889ca" },
                { "sv-SE", "41e294f8254575683f4a31ad974ecb454d295128014c7faca32378c6a5a36958c1db01f1ca1aa97ac8080ebf5552434f5ebd0d546113749051b4da52105cab3c" },
                { "szl", "25e5e75f0ef6345a87db87af8bca99f2cba5b25b9b2788a02011dccedac60f0393ccae9b2d3d9b7b7338fe18fef86901a7367a310c9ca8ddd9b50bdec4003ad2" },
                { "ta", "0c99cae2643be418ffc5d48f90999728f696614453526db0875811f4424030c60fd6064e596d8964042c7795252d6c7aa397c792c4fee039e7b71f29116f2ed2" },
                { "te", "548362144e45402b14d481e24f4fddb9a4057799667ddbc83bf8481ed004d2ed683f8b5b36d3134106333dc067ddf7a206678f375fb9945dea69836d69f6f7f2" },
                { "tg", "ced1cba5f23e0b426b0efd0263c98fd52721e459cfe07f60de833bc39e87db631c6c8906fa6c4bd39b6412bff370b0296a3765262edcc724bddb467a43c876ea" },
                { "th", "c417fb0dc904f18caf58ff98d94b4a1d97dcabab005123dafe281ab5be2ddeaf220c8804bea28a5fb09c89ba25c464e9db388d98465bd2fb2f105b72f0142052" },
                { "tl", "cd82d971a83c1f517249e1186cd60736bd63c2fd881f9c55fa6acd632d6304ec85020e329da33f7a69d8c16208d6be2357ab96d5e33b55bc070a5e633650394b" },
                { "tr", "24c8994b6843a335fe58bb3d3f47b3336ab5766b2cf3acddce74d54079cf7e06c3b9948fdbe203e37fac97099ea8a55fd0e95f0529550d0ebc63e2b870929f7a" },
                { "trs", "586a28da514ec6358510166a82fbcf05aa24de0ced4dfaabe092b8bd643e345be7e18be0026a76e8149be3f84f6a89ede4daf949a21321835247405f741738d7" },
                { "uk", "fd46c5a102e9442fdec536ae04fd173ce7e6bcf7217856b2c10de3f43b05cc7ff605f4c846d5d13619f9b1e7a3bd9f58a264177d61a68cc33b8e5b183c484948" },
                { "ur", "b988207e5b68c9a2cb2a0807ccf2071866ea199877f55d80a7765391baf12b086928b1e23e342e7ebf5c64a053fec1b9a4a8ee7a4ac624ddd620af64aac26adc" },
                { "uz", "e5ac81c364af5355731b340d2988d7960023c2cceb407d183170c8ddf509bee109b4479d41624fd0f845ff44679f77fc2cdfb0129340b30f9bcd9755e415bd5e" },
                { "vi", "fbe7388a3fd762a19e4a7a03219254fe72a911a0b23edee4e8eed3845d090ed56f42f2c973e6c997a2012d50b24126208dbfe93da87f77ed03e478f8675ec9fe" },
                { "xh", "32774a87ec9c00453d6b8c14489787a4729b78124feffe96ddc8be9d7dc337c4590eb81a12ff316ae536d42e960f7847be4ff1869012c46e261ed221047bf3dd" },
                { "zh-CN", "829d9cc1b236fb0eef293afa033244a24db39ffc9c9a95b7f29a51ff2a2df491ed209d20065f3819437942cb737f7551851a54b2b6f5f5bdbb12faeb9a00b522" },
                { "zh-TW", "2337566f42d015a32da3ec0549b20f4a7cd6ef0a7b0ede66cc04aceaefa0f12eb694beaab1a258040d60e6c902769c4f573760e19de4cee1d1a41b48a6fd7806" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/139.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d81cdbf99c00777f39f72172a703910f3cb92951327ef8982beafdd88c4ea299b0d594f9ec2576d1d917f5f2ccd3d8bd6b13724d8a2a85a585612bb801c17d72" },
                { "af", "6c78f176800e3f866469cdf58b5fe9a75e96080e751846b1a95acdd3bd6a51281624f37a261dad7d5d128b2cce9acdbf6a11255a03749787fd448d88f7e3d0e0" },
                { "an", "bb0aae0b89ab7f42008c465070770385ea832302310d0059fd95816341c6555d8e12970ea8618c1c270310a410e8e3772d5503f2cbc284290937776842787544" },
                { "ar", "40673dc134711bce8aa6871b95f2878da8a3c8ee8ba71f6cec321e85d1f160fdf1e997f7e760dc0a429adf4358cdb38939e2e2af3b9c4a5daf166fe4359df3e3" },
                { "ast", "dfb4217cc684a21238c78efa2d935167b0e50dc693edd72e2ea17dc86df729179929f663556f92f57ab9f89d3b0caaf41de511ea6123820e0796bba5c7368c34" },
                { "az", "c41e4f65407ba75dae327edc4e5f6f03ce7de2efabbb230269468c9c7dc9ecc4e92a982e4c378d65d8beb2a616d828009fc59856279d5ceb449a8507534c9b11" },
                { "be", "0c08cc9f477219d9cbda9e11a6316c6df2bdb58233741f68ba4efb49a761892612af67bcc9defc70a784bcda5251da9c3eaad260796eb837cafe2a78c2b2fef3" },
                { "bg", "9a4670ba93ac4c7801ffef05bf1801517fc0346cdc1a14e58275de18ea531af6c0a119379e9a3eb10539e815c3b620a187826f9d87860f9dfad59de60559cce7" },
                { "bn", "bfe42db142e35f1989c9f61ef091e9c038783f1b2f34d23b499e746053e09c896c60aabeced600e9f415259a5eb2ea5b32a4fae1048a771db189ed01fe257de2" },
                { "br", "18ddef9427e065c7c68bf6a95b6027c4580292f3ce90fd74f5688fe14fdfd129b2f890e2c0084fe9870473abc1790c6e0f38b745443aa4e9be3cd1cf2d395dd5" },
                { "bs", "8c887bcbb04f253826845105b748d6765042c3539c2b9899a1f8a35045f1ad3bfef1c53c594861715aa6404d74598d973fe46df99abc402004fe83fd23abe665" },
                { "ca", "ddfccbf6c273261e2a11594f6293b8e385c8ffeb81ce20d4bd1f735f234543550b9ba1b96d563d084400d2428ae69e963967a7aed0dc52dee2034556fc4469a3" },
                { "cak", "e3d5924dfeea76b6661cda47b05e83e869aa16e5f71f7d1a2f2fbd7e89d8d0e35de2ece17f0a90c07e10b66f45610893f553deeeca0257158d971d3cdbe067b6" },
                { "cs", "7815fdd45bb821bad835a164dbc676d68472e59ec8489abed76ea8cdc842eb2c178f5b8e64201c6b4a47eab6effb7bfd1037756860d23c7d5274f9cab8c9e481" },
                { "cy", "ae9d8cd27194f3ca84b90f85627573c9150551f99cf981ceee386d36c63641c36881ff7effdf100f2b5b386c0a1020b38f4108ffbe50d6a1f6158396e3dc0e54" },
                { "da", "008a86e59eb8ce69235b36e36d9c7b5b0ae09d6ce7b8fe03e24009fee5e69ece4439806897edf7399b65fbd26464c99c4af3a8687da17b3d5247da7548b722e1" },
                { "de", "c7607c58f0c2815d89a93483d4493f43836eba1b972a4b62f5becfacb58a1323c21c71c3b9eff7ce47bf103d88eb40ca92c2ec525ad3a8e8b945c7d1c151b427" },
                { "dsb", "576d91328367fd4a7118d60bcb05e166f6fae5ad6f3d093d12c50a807f879d0530bef40b3e6da1fc42c74494db2cfc5fd128654b5bb5290913729bff015c1722" },
                { "el", "5ca5ac098437652dae2de09c94a41e334353ecf60bf0f51b0d85e32bb701cee18199d408be7cebd42cb1db4734d8a8d8f4521ecedaeca50e4ebfabe20e82b100" },
                { "en-CA", "75c1ea14c41d05a0d7bb4b5a5b7b81653fce666689ca36adc86777df3014e9caf3a52de63cba7461aeeac9572aa5e34ffe17ff50250cbea1d8241e040fcd9dd6" },
                { "en-GB", "f322ad64e3cec77cede5ffb8d8e70c94972c1482b173d7acab31b75ef87a5e3beae478e488b3a2bc02319b95e23e0481e15b0a985b8ca2c88c66f47839034df2" },
                { "en-US", "1bf6f48bcfbac93251c19e339fe0cbaf27b34be0426e1b80a3ccfd3d0c7ad7ec536d3db6da7168be20f4db944f3bc611a0b699d1df33bfddc683141543d74986" },
                { "eo", "9ab2191766829da73ef181f4fa15dfb100b1ad939add3e27595c56b1c8d4f32df15ec107cf94310ea3ec1f22e20f0bbbd4a178233660b2f093af47e3050e7ce4" },
                { "es-AR", "c4cb81c8a535852e632f49b08b7c61eda906b617f0abc578a04527b0b64e7221556bb4d027dbf2e18289c16ca1e811e577f8ea211a41b49c014129e387f3d449" },
                { "es-CL", "6e2797bb69ab6debb3c2e53c8a946aca6263937642ed051ad714dfe8d827841e1b5d47fcf72ddd1c952f9d26bbac4325bc8059645eae2de5e44c0fda1c2be467" },
                { "es-ES", "a2c30024c388e2a464c2459d7f61f34bdd8dd950e24735d7e661d2f0ad0f7e1d3941521ff3971b1ca39dab771fbd5ee69d0b41c3e4655700cefb6f3c8af2d672" },
                { "es-MX", "4379434819214d0fd506d0266c170dc0dc3a645536907a9eaca9e10dbf85a3654aad6e00ff395407df78a1ce81ba6fcfb70b859003a9b0410350feea065c8f79" },
                { "et", "44bb26d388310d6066e8b05af15afcf2ce65860fcddfb1f5a619778673d5aa61f5db8497a41f8502fde7b694ca6758203019cd7cbcf7e44435358aef73f4922a" },
                { "eu", "7b060eb4eb3b7b6178239c988fb0acfbd4b7087d346f6c140d353b925c9f4e0a6f1efee522fea50ee63446b066e093ae56e3d917ea9898ecc737e8a716e8d6bd" },
                { "fa", "83b76a462ef686646a580bb2c19e3d042557cb0fed4b30e6c4e5dbdbf096a501a78cffca3c45737fdefc04c3fed06dc0b192e81f68719e3c3c7c8a3a343ca0c3" },
                { "ff", "41a08910815470df17fb82cc6a49b0ad766d414f31ed1ec463eeee331e3bfd32d9ff7c65a8420ece1ee1cd014d446454dd057c8bfbdaf029cf5c440212b5feab" },
                { "fi", "375a57f798d76cdbd26cdaa98f0b30aedebce2a15a361da164efb724e4cc10e9dd9cdc6c15e7278f4824e9931e31aa412fc08967d84bfc4d83d1bebc6bc07ccf" },
                { "fr", "47c5ee6c00513cafc13d1c43e77811f7f3bb0064092c5f4c7ad9bac5be8fdaadecef500b616625b5c8f2358b323a6f9eb8aed0b1352fe06440d870b28f0f8d95" },
                { "fur", "c4b7efe1f92065f0173f4472ee7ccc4db70aca33769e96f04429d1bdd9c4f0911c593bae8c1eb0fe0ab01aa52bfb7673c9756575527d998cc39f765f68c671e2" },
                { "fy-NL", "2e6fcc33d61d3ed621060667344434e101395f5c8d915dad5b4b21990530423300f1ac19f637e7092a15edcdfbcfd42c17e890d42439d156090847ee6bc57448" },
                { "ga-IE", "e79b7deb059bb06a562f70da5cdccf7b1fe02b93d3534dbbcf87ad1e477cc1777838aa0f8b41aca5b78d4d89cece7c6cad9fbd56f5b2d06139049c03486416d4" },
                { "gd", "0010da689daab9883b2a3610655ebbeb293e08fb59b1f32da7a63ec62d6b3a1c6c10238192600d0a174b203ca79415f3af30b061e68712e52cf4043475ca3465" },
                { "gl", "59fed4c60305c725718e5e6508809d3762299122b3a98ead743c3eacb6dfbcd6790a2fbd4058e4612cd5656259b4f2a117f4a02e422c517ed8831d9c6a9db6f0" },
                { "gn", "44ef5ca34e9900bca88fdd0d4c019c254477b51feb97858a82efc4c8603849dcb7edac58374f187211daf18461521aad4031426c37a1022ff4238114b3869643" },
                { "gu-IN", "d424ebdbb795aab86e779588ff8397ce5b2e989c46aefadd59c7a92d2277b3d4972f06eb78d9628df24df04727eee4c04dbb1428f68614931502bcc2e6be51ef" },
                { "he", "94066c77ddb38bab43a96011b094a7fe2258895f3de5c43966939e6f817f83cb97d5918f2228f460319b16601067407409c8d584343c650e8e4038bd41b163b0" },
                { "hi-IN", "5a2fedcd3de41face22f203b68108c54d8cf4e7e3d0089892dd3b9361696693b5cc7374ebb6f4c5d10f30949973cd5ab6385b74d6d50bf2abc16701c68ee2523" },
                { "hr", "070c20a713a04956af7becf69b19b438dcf6adbfbe748270e75aa124d903abf0baa3f66c017daeb409f98196a18d4d41fb6a6c8042a0ee5f98514f4eb3a1a904" },
                { "hsb", "bea6651bd3bb28502c12d0b9f7e7742a7dee7a6769d514956e6f5978015be59623f48b94a905ba5644ffc7163da2ea254fd9b2d9104c822f6a6360faec62f660" },
                { "hu", "0d08470ab76797646bd4a0f4926ad2fcf29b3c47bba9bf420c6c7e80158ba530a227b68fb9001a2d8a021bbbf11d5b9f23df99ced3f80c6a22d3cd78c6dfeadb" },
                { "hy-AM", "58c62e35a708accbf73674c501430dc14c19723105b7c6c3ae1be178ac3c15d262a1a56ecc8ba35a133d0ad14f41b70739fe64bf1b9363042c59bb30f0468527" },
                { "ia", "4d76257e4b512069a0cb83ffdd6fa610f327ee14d3f83b0a7b43977f7fb92e818184907b9dbb17d21f0faa4e27a53527eea0f41298cbd48241e2040ae669846f" },
                { "id", "6e22d48d34072a2de2eefd21dd63d4d7c1cd16b18674e96eb420903efaadd3b6845d9c5de4bbec6d17d74a781eb95b1be64fdb46e9901fd9a2c4395a4d76e687" },
                { "is", "3b89b4354399c60aeb9800cfb485105127970bf6d7376ca626303284458bd32d7a2ddc179b0a090f06005158a8d9fd58695f27f4608635ff8f26d590b14e3b6c" },
                { "it", "8a5eb0deba506cd3f5af0a76d3aa5f1504fa61f8ffc4f270f8b12103299ff41cf6a7fc2340d6d4482f31836cd4c856222a9bb64461301be714c25fedd1067b43" },
                { "ja", "061052f1f0d50226ca7606d0790cc40fb285368544b69f5071684ce081e3e3312fda62a8f4e61f26e5e1a1ddfb340a7bb10ba6e337f52744d7ed3d033d616f0d" },
                { "ka", "ea01fedb1dac013e6db73b71bd164f568d196a86d1ac31322fcd19f62b93ad1f82afdeffe000415c1e2c98bc298821ad91dcf087d0b04e951c48905b8bc19555" },
                { "kab", "2d5b2ad650e7b27949a5c286ad63eeb1fa805af468cd0826a66317b1054c448f0b11fc4731aede93d2fc02b5d848acaa5fcdd4e729958de4fe7c68dc33f3ab76" },
                { "kk", "bb82b1908bdacf625105504d02c070b51e1046142de17fd4b178758dadb889106d41b2640f3cf198e3d0dfcf0feafcd91c935786073dee723913946ec8f947a2" },
                { "km", "8ba1097e52bb028be1b866327f89b5f8bd517be965bce5ae00cf95b68b8da217774d177e90e8f48a462fb3c728678ad9cb5c60eae685f34c9be0e3dca492fc0f" },
                { "kn", "9918aa63795efc66520db731244ad3026b3904976a3d36230125184df8ebaffc0f19aae7d383f7c1339c8e2cb9c8774d22b38b624a2a7b00bd444f906589aac9" },
                { "ko", "642f354d18751dcbdfa4a8ed127b7e836d8b6dbcf446fe046ab1d3d6ea40d40171b2a3e14c266ff098555e61fd278bead8202d3fc01d7f18bb9c9a4f7930edd5" },
                { "lij", "9684256d7b89ef52a9cc027d4655179f4f29e0127b898c8f159d9f414b67a2879510970bbe7ad87fc4df83817e08800aabd24cfa2f3a1d0f70521027d8b8076a" },
                { "lt", "c22499dbdd18fe3a3f5558267ef558bceba52ae325e7db9280ef3374bc77a67d050c80a10a669724c66ea5b34ef39481ba68f3b569a7a77f100daa48de7061e5" },
                { "lv", "8f1cd0409f3a5e5cb98f47c0b440459e56db7f977b65b57da6c0bd9ad5afc0b016e4b48be45fb5f24b72621afcb5d3b89c5c6d747eb8455bd6053b176be42ea4" },
                { "mk", "eb32a9aae654a0aec428d50b9332769716fe3d5612eec56a95c122c59d749f31a834f213d5a9fea661afd0648374d6157805943a64b18330c4435dec977554f4" },
                { "mr", "7636a6b9e22475660a8130cb6b60fafb6c4e01a4a197bcc51138f7c1a739308acf4709b773d7fb51b58af7269627c752a142ac4a8b884b9cab85b75676f0df13" },
                { "ms", "847b76b6b83da953b67e632b550abe41d7dc6de75373bf5ac53e049cae4862076d7da80bb1b41d4743557293d0abda48a71c6f574eafd5263392d74a7545d832" },
                { "my", "1ce6362659581a871cc0c4d72039f2fe575a82813d8938b57a87e842f90194af84be7e65e6b139d4502dfd52ed9edba6d319223131e9de38f78bb6e99ae25ceb" },
                { "nb-NO", "82b9c95517c2f9ddf9e8e56e8b77fdb2d206b66df41741f3551ef1e0f217bebc3c7d4e4e0ccd522b12f9166e5b69d1a01c79cd3450cc3b82d14f5dade58654bf" },
                { "ne-NP", "b83d8155d6e1c4e408ae92b6187e41b26a02dfbd92c31f134fb9b510e579c6ae3bcc1ae7cb7e5cbde778c737c6ff0ed21ef62e8b7c49cdd2170c1896931e7fdd" },
                { "nl", "92582708020f7992bd78ae0f0fc87d8b172a3eff8178b12c6aef79a015d9f5e6ae2b8bd266a66a5ce29dff00c1ea979932f3d40a4d4c06611679ee871434e360" },
                { "nn-NO", "1bb00641b471b656c9da64491dfd44dc7efcef9e61cde9576980234480ba35ba26308209c74288ae210fff741a38ee22804dc8f976e79dee2d3c316c1893bac2" },
                { "oc", "ba2e42a42f75d40ae974370e1f2b3af6c3c52dd18f332bee9d90c6d3b4445a497632114c86d069a72cb4df1a91d54871aa4701df1c9beb494ee772a46742984b" },
                { "pa-IN", "706717f897fba638762c740b8e3a43571c08d7f2e8705f190e72acb40149e47371d604082ff44bc0b75733a1a009adf94b8bed74e6ff7c1290e158ff2f9f8543" },
                { "pl", "6426b129cadc0b4e2b444d858099dd4a461ddc9dff5460173715a33b6b211230399c3ef1bfcdb2817ef8abfdf4ca08e884e6abe81c4b748b1ceddf24ada42e7f" },
                { "pt-BR", "239e793f98b71ce5d537af45322fc416fef4da4436ad54ec6f48182a5f769b68b8aef8d2d1f4e5a8926a39aff4a7294572478c53a368973fdfa88f5addcda8f1" },
                { "pt-PT", "61bf9a1830dc703fee0f290e9c99b10c0b6f2957e421d18b69681481b187299e52ac9ac132cc6da52b571799c275117df8e94d9d5b388b29b02447d880ff03d1" },
                { "rm", "2fb8fe1fd771f865d72e387fa1a50ab8bbc38a3e87ec87fba2ee02d5041840e76eb2b43f8cdf53020e6004e4e541bd79d3c13599547ad487a7f7ccfd75f9e76e" },
                { "ro", "f60294224da618d0b5b38ac270dcb77286fda409b5d47193fcdad7c6d27c0ec332e4767355b779ec58523a936c12c1980caf5f5fadcc1e7ec74cb1394c4b1c9e" },
                { "ru", "fff0950f3b110bd9eba27650f8a32bbb9ddcb102f48771a6ba2a8007e1ccb4cf92603bd75f4630b3f837ae7ac2e0a324901b52aab2464f6e1e584707b223a81a" },
                { "sat", "8006cff7b9e7c922610119be9d55365bd4857bcffde6d3e2f69da3b50055f137a77601225d4dd7a26a28a5c37b6c8c3990d6ef2fdc2c836ff0eae6242e44e69f" },
                { "sc", "5d9a6e32be207d0da5ad825d9fd1ed312caef2880f0e1aaa4d2f6961c1a5cde558959e3640c58e4b1a71cabadcbef88b99560229ba99d7d5b444ef8bcc913089" },
                { "sco", "52796b9d7a9f84b5c012afc9a91ac62464bc8fd16f54156b1f68d49e513dae21cedd6dd4ad9d3d5b3052517c8c70985fd527d8e9fa189b3f5e6b4581b14888a3" },
                { "si", "69a8a7e5a835404e7ab227c49cdd58f4715ed1b4ff93cd09eb0c49b866e56aa5b79c41a0b9e4f625412bc28a23974a907ba961c12ce354d3b208f61217a936c4" },
                { "sk", "f93092933e38de682975d8b070c8ee0edc55434c58723fb547971c0718a2a5f37e88c584716c1da062713aab7b91c95d531e89544c5bb54be34aa8c235bbdade" },
                { "skr", "fbb79d4cf0e13729d486e4ea6c46651c18d31a9c21e3a9662baa50e37123b359889481ae1461a16fd73e36d47be0d0643e8605f6f8d913f3ed7893474ce78979" },
                { "sl", "7f1e2e21dba7bb883946b6855e6fba9c40602d9bb97a51fefc5a2d7b0d10d5f23d47fa5f463ca725805b65ce2de4e51ad6a512e3792de1ba5030bdfafedc066c" },
                { "son", "bb1304f10d2bd97f9b0324af7391687a10eb0f50c113ae0980ce8885ae0a87da26cfcb4bb8d1adb98ecd73763285c870911a4f226f77e538585ffc9b496e77aa" },
                { "sq", "4e01e81020fd1e993555ca26e85018ac3cdca5d9868eaccacf7ac9bbf857a2a1a348991e08bc8b3fea8513c3f4a8022db6ae976b297670338f329e99ae0da187" },
                { "sr", "da29657546a0fcb6c11815c8d1c1ec1ffe807a0c26365559c6391b606411cee859c1fdd26ad1a61e26d27379c60202b009e40ca6ad24cb88e65dd7e40c37ae59" },
                { "sv-SE", "3f3a9baa469a4a060e5dd8117b3ca4e50b89daa39d6390609d604007818ab90cc961aaf90ccc1f425360ca0b069c69da7e4b1d5a40c23e66f8d77deace3a9285" },
                { "szl", "6c63424cc0b65ebe44d80acb9dc640c6f7d78c641bb69f62f42165b4d51bbc7ab2a8085455dbacd3090449d0b238a84777b48b1c32719389c629cb33a3d0bcfc" },
                { "ta", "02d0c20be071f98169cc68deeabd4abaa5fa84283f2689c9dbb12154addf7a5c52bb58c00dfbefc47227895bcd3868c04ff4c148a6e07c7385db1844129c045e" },
                { "te", "eece64e5ef4cce3cfffd1801a0a4920367631df13b594c868aee10116d7738d1121b2df96fece44aaeb737490baacdf9e44cb37ad01cdb0e7d00482005290d64" },
                { "tg", "c0634a145c60cb73c488b9422184b5a11ce6da80c9b9e91f9eb02a380d2a4dfed73b73803519255b213ad638b0bd6ec81e78d24c0f6ac1d89b19570adce787a6" },
                { "th", "9f0e2926a181b737ff129d3ea0153c4433163e65e20b25d3723df09794fbab5095fe6b094cbf053b4ef0c710439afd2cd3eef23c4b8f246697e459c343e0cdd2" },
                { "tl", "7db93b84c468a3c93ef68cd14dab00cc6880ad3a31a8f96352cabe45e254cabcf0bff6c46e580e23381a7e587091d8ee055ed025e6677ac2d8c551b0ca6b275f" },
                { "tr", "b233280a5b951998aeb38a9a894aa6728231f8388af8f90ad99534570ea51811426fb4be08ce35071c4b8503bbf05aa97483619c931df7b21974a371a9f66085" },
                { "trs", "78bd6d91ba5fee521f2eefe2d465d1586ac055ca2b0140cb5093cf05697b1b6e68d02741cd0003a490fc8bb66303a670e8e93182faa25c58e9e3bb09d3fba58b" },
                { "uk", "997085df93605377ab4cdd581d5adb61e783080409dda702f3fac0eb85b534da13e9e3a0766a5db053eba9e8d968ab576f43ac2aa6dadefd65fd6b3d246e0eb0" },
                { "ur", "6eec9eebbe25d9f130521bca3906761694933d8aae8a24a142fb6be3e8a746e05e07cbef8bab28ec39ef14cd4a0be22be82cce7600afd89e0fe6319fbd8702a9" },
                { "uz", "16cafd612bdcf3ae237e5d5d902f46826516077474648db8cb51ecb9d000cf3d857ab419a30b02a2af6e574e8fd1e1f26844b659720d87cae5ad01392e842e93" },
                { "vi", "1363d8ba02538a23007ada7056fe2116dde1dc7bba8e6aba4a1e1d08d60a4a23563d8d01d47ce5ad02842a0e3abd6e74058cb2fcb455876dbea7918e5c27fe97" },
                { "xh", "423da25c82991b18beee70a2ef321e833ae50b20c3c3ca1086b6cc900e7dc246191d702cce24773a21402eb336e841a62ba34e752858ae6f257c3fbf7c69342e" },
                { "zh-CN", "e9ee097cf57f868dfb453231035681f487ffa05f2d1d6fdee9b733e9477fcbe7d1ed6afd13eb363f746796a0d2727aa62142f0d81a011c1a02d79089d538b473" },
                { "zh-TW", "26305ebb2fcee8994a6a50280199a637d2571c02f046b7df26ad1ee7454f99172674109f60be47e7b803beeea113dcd65bc0aae3e16a629f14bf14812b4cc8bb" }
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
            const string knownVersion = "139.0";
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
