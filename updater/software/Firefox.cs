/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/149.0.2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3a2cfaefe4b110999e9c726c545a72453176fc81984fef06b9d15878260300fd7b9b54b3a7753ce258209914aeab29b29b1d6175d07f5170f6e1fb43a26f6e05" },
                { "af", "df9893f007e7ff78c3594f6fb84ff58b3214dacceadc097fd894feaf8a4dcdac4cf2d3440211168e32678173c61691fea894ed218350b620cd500aea8363c40f" },
                { "an", "4ad59678eb761058172432b6afc8ce2ec7973225d03cbf3a395575cf5e2fe19aed86eed80e4d64750e9934845d939e7b7c00b4acbf7cce14e7f5a08792ea7598" },
                { "ar", "184f9034ddca15f36ade1e00ea634686a0955879e4250e1de38e683e42995ec3997431fc94974f3791c17fd0447a02db3774dcd55831e687d8556dbdddca8725" },
                { "ast", "15af7f302bf0bfe09c80ef55a053a8dd7d29ee398b0fc65f33847ce6ede7e18a048f1c4b6fd1a917ca95f53d5482edde028aefdf4f7264990d29573187fb6b4a" },
                { "az", "da92c9f7c9a80eea966f2fbe552f36a3a80b279689b264bfc072791c452f5c6e76854e286606672f8d9d676471b6e50447fd1f30f966bc0aff28782ac9a5401e" },
                { "be", "15cb14d0d2b885489b330b3372c5b0948d73f8f0dc3d4a9fc397db2940e36b655ec6573f34f89d5cf0c35cdc7c181fb29019806bb2ff7554cf4907bf2c35cb6c" },
                { "bg", "3546a848b8b4713c1ea7845694527d8d2c1500a0fbcb19398c2643a8c2038ac2353061779fcba2e3efeef62ef4b5a0480264f8b5d12bc1878f75f24bc347188d" },
                { "bn", "6ac79e6b3c3324f649ec84773c3a9f92f0c02d0a37228d10e7862e26ab6aaa6e46166f4eee0c9ecac5857e7081c7c5a74209feb744feb995423548730696bcb0" },
                { "br", "def3791567fffb235b0b258e59d92718bda6019f9f20758db99897bbe58a15f47920ab940eb89de529042c853430cbb9dcc98189b268e4e5f94b6517740d49b0" },
                { "bs", "08bb6c5b93da740ccd95b66ff23684176a37bec712a12f90695201077470863e5b32d3ad6954a84a9cfcd13ea378993d70a88dcbedfb9f7555023f08751b3e14" },
                { "ca", "0792f4ee8ae69735cc44c4bf83a4566f032027674ec0c5611b8132b75887448adc2949459fd40c679d491f14e8a5e9566756afc4f522af62d8ab31b45326ab1a" },
                { "cak", "e1ba0a9f71aca198487b8be5968c51567b773ccfca548b5190a3abf787d16bbd3411568a7df920ac2d8408773e94582cba64fa151e96dea89bafffa043ed9661" },
                { "cs", "8ad3c0555540be1c1d41932a35e79d4d665875d5c9cce29a00c40b3a2181aa0b5294bc2259eab59bb9f1bdf3690f562b028f659f4c4df98c0936435f27724899" },
                { "cy", "a8bb49edbf12698a5164ed1528fbc13287577a0a5affbff9441f40153222657704bcff103ad932b9c57d0df1aefd7fd5591d0d98063be5d4301393f0bfb5180a" },
                { "da", "4f5247bb5e0b85a7fc2febdd6dc86c3e0c1e5520796f78938d1e692036d7f3d09e7bca99fab3cd32938581981a250bd4810ce950d2a4ba9f6d2b69f0310bd011" },
                { "de", "14c6de05d43a1e4e7b05e86534bc7e187eae5574a5f32a0ee523a93c3cc7653a237627602b59289f436b6e24328df68d1af55ef5f2ecdc595af2e6b12eb07ff5" },
                { "dsb", "0fe67ecac39b6e2c768a4c43c8b57503d664321ea10a391d77df29cc121d6006f1d437d77d805de29fe4fd88758e66ddfb55bb0b3fa6d247ccaaadc9adf0ffc7" },
                { "el", "4f85d6c43e9b3ac4be6a89e0f922578ec5b1618f100861a07639b13693ea3261c6613d6d9465924dd709ecfff89c218541568877ede5fe9be7b3eb8dbe8ea71b" },
                { "en-CA", "69debb3d08942a28123394768c4858512bce91c9edd80833a52f8c600d9dab154f0edf134c3e64a3c8cf586b0b0a86ec87e9db20eb80a5dee06604829b0cdb49" },
                { "en-GB", "67eb693faeb89b538b031e822e5a08651cd3997ee112dd6feb69f4f56f8a2a6e9a05f6a5b135d0bce03810eeb27e6ccbdd007639984344c2d1d784c23af275d1" },
                { "en-US", "3f0c61087c262354e7a01aed69fbbccff72c7cf27bc7c8b2e474567f62b99284258707f8c6ce2b6afe230f1053dd43a18c8c2fede0ffb7a33e8954383dfc1bb2" },
                { "eo", "234f2dfc3d856e17a150398d5a06ac4dc4ddd27d3617f3610f55f382bfecad4a75265f4f628112b9806527469c597be17b1b88dc9f998f2341e74787d5d7e536" },
                { "es-AR", "eca8e3eef1c9269f0e941922c1573baf899bb46778cb7762ee5e96b243358eb350330cab6c4d9e8619cc7dd08ff1e8e3a47415c16da470fb12fa9a268d3fa6e2" },
                { "es-CL", "2b5959b1e46cd2db75179a29a067f1b487f5769f49c0d08cfcdd389fc99cb5f35ea468cb0317df3027bd743d17f6776830d24cfe5335a6d12399b83e2e9828e5" },
                { "es-ES", "3117ca91d3f6467cf981c40f75c8ecc8ac614e9a833d59d9ee60d52f97abe03d8edd0a8baf49e6d2234ccb70679d0cd2e13adf71e17b07bc1386a8de27a9e762" },
                { "es-MX", "fe852c6494884dfaeea7c3b07c5c45e4403936417bc3216d2c3af825187af3acc11673a9163659cd87486c8623539d59a39ab7ed2826190733ad2fe90526fce5" },
                { "et", "c8a4f377e9519767668eb0daf2acfbfbaf903433cabac836d9125e1e7a2f1a6f71e945a537169691b76fa4c7411b47829a2bbc8f453dfc80a4921f26149f6529" },
                { "eu", "b1a1866ea6d56b695fb25b48fa8f4ff2f31de2aca73321ed3eb42c84ab66f223cd7b2589c839ac1271239d6fd05ff611d1b3d618bf29ad388087c1f90930d843" },
                { "fa", "0cafab20d82b35f8bd4ee599cbe28053f01eb5aa85d28cdbf3517192a1642a4089ffcacb98a3e484c11839d10ea986a5cdbaff89bf2244ed3688f19d43bb5b89" },
                { "ff", "dc7779f069b3270bf8a4c651d2f2ac851f3eb7c26f0e2b6108ec13b281f4f8e1d2c3ac74e3d41b5c45e75dc8b4e8bc486b9da14155a42fe51e1e8eeae9bbcb30" },
                { "fi", "98492de8e27e0d352f8936b147db4f54b8003f645e6e8280ae29456e494056222318f7010538e582a2cce94f70e37f7d6ddfcb1f198e063e688971c30e59479e" },
                { "fr", "ecdeb7651b2a3172d2a4fd1cda4e3233856b457215543571e34b3a33bbf048ec056bc771e910066337282314a45f331fb241a2f6c8bdf346ac3f3d308d616937" },
                { "fur", "050cfaf613e56bdb08a09357d99f197a5689c04df2cc88bbd9d99b200257c72127f812b35356d35eb0a31e3ca82060353077e1c97c3e6f0a0bee46e1eae1ad85" },
                { "fy-NL", "778623a0cd1579116b161ddd52c890d6a039d70c04eb434cc5b1b2ae9d518876cd47ada5b4d6388d991c4a21dc2c7ba3d65fa8022294870a56ec8f26b9a42b0c" },
                { "ga-IE", "a1d539804eba68da9c37058677c35da0d93b911fcce0b912621fb9cca94bb1a7a5ea4deffa86cb0e75dcb90cf2d971086e583951bc2203be0a3f0d7d2d7681b4" },
                { "gd", "d6b370b3222c888e319bc3434be5e2c1a8c1b368e21b9232e4bd17870883eb4373c5601d3356f26b275750a81fdba0c8648b1137398ab37951463e200ea30733" },
                { "gl", "19da27ed52274c79a3cd431334040d385456bf85c875b7c00784c24bb75e4ebbc61c131e0dd7df4b244815e7d0b3fc1429d0d645a38d73fb2775ccd915ef240c" },
                { "gn", "1273156f0e64674093828846566d9d66310c59df1b2b8a25e5feb0457441b3bc04d093439f59672703c1dec539dd856ab5b2068e148a51d106ba0c537770b0a4" },
                { "gu-IN", "025e546f9a2f4a5f66f527140826783c144f363818bb902e8e3664703e23dca371a4ffa7cdbc1a592d502056f41dc4a45165490bd7460f9543a5937b9cef5229" },
                { "he", "2aca17b8d4de76a19ceb1a63e1cef72ca615f1c14bc08c2615e49570c83bb2b89996c0f0e4a74d409e615887efacdc155843f0b3f66e19e437deb504a5fb6e20" },
                { "hi-IN", "c106356dc918aaa1c6d26be7c5904f97e04229823576f3d0efbf072d0ff5c4fd0d57ea718a0084195c465492dc3bc600f217c77f8268f2f9d72e95bec88cd943" },
                { "hr", "1642bc73f023a37e80eb79accaef0e7f11f9c4d3daa95873d41978f322b9cca0d682ff491c5ab4034643c67dc12a56462af1efcc0867a836d77ae371ad900055" },
                { "hsb", "0fa1ef29e7f07e562df68323e626b6fb6a4d47315818e3112da2b03096e4c6970014c34fcf6e94ecafbe03f821b559abf0cdbb21af195c8cc11f5d5082ff23b5" },
                { "hu", "21d06ce0162a25dba51987518a4d8c2e8d0c4b58e959a5165d6e0ef06862c2931483189b84d5d9b4676ba74c01293eb74ce547c9c8a0f9acbf90bfe5fa43ceae" },
                { "hy-AM", "b2885f090becce995aca0280dec16800dec0ba35e704d9ccdb1b589be85d11d76ae5e520c8d59d1234cbe020b737fac7d30e8402cdfbf57e0da5a0381e52efee" },
                { "ia", "4478b637d3bdc19cb4b135fe55955363a25124299ed01d897a3c9b3bf312ca52ad8bae63bb975fe69dd76a21a80897e19386adeba038d748a17d65e90945d570" },
                { "id", "eee9600e1379176818ab69c8562352529590442ae01a6de4efe621f9cfe6c6691dd77a68737c6b5b9a17d2868fcdfd05af886d01a4e1e17ddc6615fd6ccbbf6d" },
                { "is", "84c6f3e0aa1adffcb39679fbd59666eaab48e67ee990b1e63d5016248128913ab8524deeebb51c394affdaaa0eaf48339308a4fde58ccd7df48a839142ca9424" },
                { "it", "d37ad9a0ff1f590d56a9d3bd7923dd2b1f4469c3ad635e43eee5301d02dd388cab6e676570c05f83d2061e500b030ac1bcba590baf16d9f4723449ed093e9f2d" },
                { "ja", "72f3e975aafb13a6465aeb509263f6f5a6a01fd83530de73679c77287dc0d909e5fc4bc56192474d601d5eb4130f7638956a7a7586860c4d4a1f9d292543d81c" },
                { "ka", "dae8a4c285364aa9953ea186b721a1f8ec13c83078be66cca72ca42b59d0ae53c40cbda2415de7aa6dda838d82c04514124fabf2575d55e549728bd8dd652ffc" },
                { "kab", "33a27aafb906469ee946141647d7a84318e9665b4a5cb412e533261a347677191f50d318d284edc7f7c894e6f0c851a365551c4bbd734fac532a7298bef12292" },
                { "kk", "4bfd8ae8fbb0abec888fa935b5bd85d919108eaaeb1f6c895d6a347fb2e98c4f4469bbced8ff3b06ff8883c9182f5f5401215c93325b20c1811e4828146b2d8d" },
                { "km", "689fb0e9c7ba5c682b67d8cb0411c56128fd9d511724acc17ceb4eccf6f51fb81d85ef282de8085bc37b4fb646f46660eeeb5188ecd7873fbdf2baca063c2397" },
                { "kn", "a987ea9b350471f4231db81d5f46a2d1284a27bcb97af23590dae2aec89823860400f4f2ea90605290b1f4adb2e874e0d1d3ed20a984c6f6b05fcb0b9850266b" },
                { "ko", "bc20d50a105e846ce9fa8eb094c2d63378d7e82da367d8690f4ecb8dfad344911fefc9eea355118c4c7ea06c65ff9872e41d23df5320bfbb52c8a476a14ab331" },
                { "lij", "9ab8c5b3a5b0780cc9ab6b50a9a3390908ea48e1247ffe413bd941fcc923fcc13246a7083df874052c7e4c5322084d4271f2839c3d42936b089c30668879974d" },
                { "lt", "691a6e46623f55b61ee7d7e60ed2e6a8f2eb1893030b3785c2f344ae2db4f8b2bb66cb353555e991e830db06c545d8c41682f12b07382270d11c3e1c915a3963" },
                { "lv", "7d24c21d581053c580bd4ad8f49ea086e12bece9151808fa89aa8133d885d24fa2e3c745ef063516d07cec6e86c5d578686544ae4892e1c1673887ffb7796fca" },
                { "mk", "d37156da84dd3e37701ed5f655448d85feb0a23075944e72b0afda6c9cbbbdb2bedc41f4b69779cec201df10bdef2c2721ebc9f11b2a3f05d52f3c749bbfa9e2" },
                { "mr", "3df1f0ba54395fcf330a4f5d36699fc2c2b0601b150139e394b2b2d690974944c15166e9c6093936363acd300b16203b25679c47ebc4bf68957f740156458a31" },
                { "ms", "aac2ac1ddbafabd8006a2b59bdc94d87e58e26db85d7849c40a308804e1016b04f7f67db7c17b5bf9e13eacdfa84502198e97e89fbe5c7b71d9f063bff9e561a" },
                { "my", "b19b7a42b7f0c912bbb5a30dd95a9275811d003480f6cc1d9ed5c25444af0cb45c47d28bcbd349bbf879ca5e775fdcdbc8fedb9e288c44815780df412625684c" },
                { "nb-NO", "471454fea64e93052d334bb20df140fd9cba8bfc64d5be60416b0db106e53c7f8f3eadfc90900511081f730de15cd9b2f2bb8e10378968d7fe3754ca45b53dc8" },
                { "ne-NP", "3fa560bc719a376cc44bfebc94541dac870c130251d98bac97a9028e9a75082ea6743b63c1d6f219ac0ef17525259847b7edd7b4731954bb5658445e2d9a458f" },
                { "nl", "aeaf7d8bdd30a3af2872bbf9672fd6c69f178006b087a580d91003ce9e2af6497c15604d19684d3e48cd51f92bc4389d02e7274d22d6b363c86aaab406c539a5" },
                { "nn-NO", "fe9022d79670f80d308c8683674d5982cd882fbaabfd258622528909ae17bff6b59666798ab2c9c39a1652d8c1a20501071b06635f2b932d9769231216619793" },
                { "oc", "fa8c6a1e38c45e9fa344f217ab57176747cd1f6362cc52c9314f14697e289ab462b80f9af5ae9dc82084512a7dbbbe43c179b272142152fbc81a36670b3bbb62" },
                { "pa-IN", "9385671315a7bdda3a46054b9154a9fdb9354d612bfe7f0b0a74a417e05db7409ed622482eeca99c4fcb7c558b486e649a1b38c45da68ae5b66688c90f7c8d6b" },
                { "pl", "8d465e8a5990c0fbb560f2ecca295ef51f0f8a09f2b134680a0c1e67e277972dbbd06da931b52f254f0905999961fb5e21621dbd57e0f7f8fbfd4507b12248dc" },
                { "pt-BR", "2c64e6cf899148c9f658f959a6bbfdf20fc48a6f023de1f7f9a2dcf0fd1e437e2b8817dac1d45cc06916996f9204ac358c2751999460ce8cb2b5aa8a67ef0a05" },
                { "pt-PT", "adfb5a8f4e6e160543cb495e8614df76a1da49edb52c900eba9636fdc9702f91a584dc13f18732c3d015e038594fc89d5f61b0b7c1c16f1e0fdd581fc344ffc7" },
                { "rm", "2195ab514307ce024cc08df9cbc4b344021b7680aa37a54ef2a7871db261a646876aa7f30c076d8f28939489672e828dd959bd6099619585a394c9ac756f7ba5" },
                { "ro", "42c71607a5ac54ae0a6a0c00000d94e15704c789ff6366b0d9ca35a8ff3aeaa2172477750283e4867693b2e4ff57d498186d652908b48db066eda4540f66fef9" },
                { "ru", "35148bdad62afa9f04cc302937d741e9042108f0824f8af47d312aece37b480531504cf7af5e4f2a1e2966d643abc07d1e9b93b008d3dbca20e21c884be6cc13" },
                { "sat", "a65e2fda2ef1a2dbe550ce691794cc0b76c59dfbb3c20a532b74cffa12b1a8fd1b8ddcd53d9d473ada0f80a86190816fdef8a858528c499e042c76168ddc30f5" },
                { "sc", "ba21b2609b47806c48d6da31d60e02b994b0a523a9c7ea297ac5b564f9872bbd2542e54ebaec3f627c01be53888d83139a84c15423001577fbef03e308ae626a" },
                { "sco", "0c538219568594efe647228f77951c12be1fd86543b5b4014fbd3a2bae3fad7a24560cecc6440ba04c43c7303f13e0ef51c357d6cfad24d16160b9134e3c77e8" },
                { "si", "26a59c7b25b1ea5917e3e3bd15dd209560f4f739e2d2867c43ac71ced43863924eab86325a485ee2e6bf133b4789daa44ada3c8aba2caba0a5540ce533562773" },
                { "sk", "b369914d09a193e11ce611b93c6847143683e569abc9706e33e9f96f346d40357fdd72c98b2637d69ffe5e6cc3f9a0fe52f4ab2a5b275b9d512d9a37cf083a64" },
                { "skr", "68f632b18b02808183df82f47f51216d87ef1a7038fdfff1a863209d97f4a9a64d43d568a9eaf7d1888e5bae51a4966d3b04159c79723bcc4fdeee249e18890b" },
                { "sl", "08db2626c319c8a7ab3d81e6c66b2ada1a59d709a813fff1a4e583abf8f54e8c60e3120e0d47162ec584895b71f5b356170b351aeb6d7c348b5dd584994cb743" },
                { "son", "7923eb30fd71a7b481ad9c8ad216d1954f69ce642745c3b2ad044c518ac16d172ebf80a13088cac7e19fd1ddc322bef8439ea28b28812963f9109c541461e72d" },
                { "sq", "f7168dc45fa6487782009e3a70258310a703cc41e35f6a0e7a98cca2ab0bef40b225ea807d8a3d8a3bbcdb34f27ba75dbc9f199d5703951bac440eb986fae164" },
                { "sr", "4936f81ba840a9ad65493cc9ee9f8fb9eb4bad5a05e1de7c7d8d32deb44be04b56724433250ba26fc8a014ae5c59f28eab4a256b14abd8877d64776f9fedaf19" },
                { "sv-SE", "3fcc8aeaa293cbcc1fe0a9c9b73bb91e4111fc7cce7fbbf84b97cdfa028295f3e3200fa9fe57232482e8915a0089591870b8ce796557ece44b0af8384e0f5fef" },
                { "szl", "a05a0279b3c70cd09f9f5fc66a7f46479ca167924494483d19590e3ed0b081c9e5c2c734f148e088c0a4561c7170fee1715ef1946a9235c8427aacad760029c0" },
                { "ta", "772d54153d3495d397dca93e710596dc4ae136ffa5b0d41aeb7f65b5e185d9af6275ef66c8c2a2a9b75cd3bf10a684bd21208544b4f94931f20acb678eb6f992" },
                { "te", "3524bcf2db416cba01041b07650d7307208eed797f79abb5c2f808b3255c0d0ab5a2958b5bbf981ca75005e8da8df2b405bce8a76cc0c44254a4f44f589b7b2e" },
                { "tg", "57de247b8e3328c979eb35e9e0695b00462fb1c993bf5f5d499fc23c8e566de40daae73372825dde5aa0e9bcec325f236f187fbe2164aa9b2fa6d5fb3bfb0a02" },
                { "th", "f11b1f53aaad0554d52c7114df3fb71cf23bce42f5810be71e8f46c56921821c2d1755a84d563e9444757c479f93fa781855536cf38a97e941bbaaa9da0e435a" },
                { "tl", "4ab6a1f94bfbb7b9f215edf28e0e980c3dc5c76821705eaeb0c9ed773658b2a7b07ea0992611ca26e7ea16d82024775a03b06628466d61bd4e09cf6ffd14dc09" },
                { "tr", "38866fd0aba5544908797f14287ae126795dfa379aabbc3f75a9b50cc979c13a43ecf5105ceb330cc40fdb3a397b70145fab2cb5244869fd6dea716fd9e90f0f" },
                { "trs", "f3b4aa025cbfd190bf683cb1dca9a9115d4615bc954c8ac32f80d17222f721fc404fd10b7f435e40a6d62a702deaa0512829424b01f4b9c4b9168e0e9b1c687f" },
                { "uk", "057cc4d8f357fa870fd08e2381dfd4a3a91d7d7af69f3e167e653213d15cabfeb13b0167bf18feb11703b47a98efd909d30a0eb705baf3d6a4179806d9cfa4be" },
                { "ur", "20bd9507bce92efdfc23e18db3622fa861922e7e5e0ed81b15f6180b62502a34016dcb68c1918ed29f2cfed925e43eb5b760cb5845def9824af8d2b74a77934d" },
                { "uz", "d8b7460dd7c69dc7211f1b136eb7720aeeaf5a889167f697698cd7feab3d2363056e0e44d96d9a5e4da12b752acdd7b1712a66acacbc587a69b6d1701bba6dea" },
                { "vi", "76db7f6769336b3706adf56930c30c4e98cb2355f91f7607367b1feaa83b8b1447eedc33d7361c952e31c9ce481f11510b6a500b0af8631a0eaf203f733e7e87" },
                { "xh", "0c437c036877fc0de19de7c7275cdc406e7d68a7a5d879934d4488b0f8c099baecb199a37a28775e99edbe13be74df39c2e68fad84423aff22607cc6626837ab" },
                { "zh-CN", "bb8259263b743880fc5b9b9d212f811283be3152eb6c554f25ce18aa8d27488784bd1d136643af08a5769c566001e5a460b8060ac9ab5b9ea34157fdbc63a03b" },
                { "zh-TW", "1b884a255d842439fd312b44be21b974ac5534c539ab80f67f37aa794035093e1e61fe9c429dee4e5b0921b8fb6a3518b33162c18b70f695f639d4cbc855cf35" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/149.0.2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4ffefac3374817067b2c3ad55098d39f21e023e48642ab2b59a6a0ff50931bc2bc9d302773a9945239b8a671c450e7247da1eae2bdc43c4c7ad7c6b59ade8f8f" },
                { "af", "fd2b142526b4b420efba86c685e999b47173e8465b03894d9429fc6eb60ae987b308524a34bcd6c5da03e9bec3782dd53d0fb4fa2e7bcdbb4586687e3e7d831c" },
                { "an", "21d811833a680ca0ec3ce840f71801345f3af4f6c8e0b7cea1615cf4886de8ca78d9f75df7b2f54d784ebd36af5e603543f1f9481b68c8a7f0c15a9f819491dd" },
                { "ar", "e2006613f5115b6fa7a39b8460f1bdf2387b24995251a46ecda1f041e9c73fa2065f8602a9edec06f9ba49b07cae584367f5332866ec61b7c4c3e8c1daa08913" },
                { "ast", "44da9e0652843c3390c35f08f29144b8206cef34b0c35f775de7aef343303d3f2891e23f1773692af6fa80e2b02cf9338d58f0d335b36393d9cb695f6e25c53c" },
                { "az", "a594c19f689f1db5150c6e280ba54e371acff0628246bff899babe9f6070eb0c8d90fb2524581cd4e2ca5f1d13b7cdc5792abfff1bccd9f3b3ddfab54ba9b6fe" },
                { "be", "878a84dce093c0cf958018c65d0b9f7cfc9a8ebf973a8c72c4bd6a0c8ea108997474e3e88eebfd07b2fb0da8014504a527d5ee27cce7445ed6896ad85fa825f8" },
                { "bg", "9238023dbe974e06894921a168fa4d8b016f3e3dce68624f59e9f3f1a7e4a28039e0157a8c64433ec610b04636ba95e86973b09a7d7217ed3739f1a282e50d1d" },
                { "bn", "9dd2f4727cdcdc9fabd0ef7bf8bdedf86a9fb94ecfb8c725a5a2eaf72f2de4feaead8e27841e16d1c571b54f026a714a19daaedacfed775aab7a10f7a4a47cce" },
                { "br", "2eaa37d730b59118c8d724742a3d0e899b86d6d8f9c00c662894de942bb37342e6f5afcd1f124f30971edab1e7d2aaefaf762fc0eaf34a9c31d431391e6f8c58" },
                { "bs", "953c4191fde8c19bcb99624718ba0d440c744e4f38f11bf4295f1042a96df7fd362c961ad2ff5c4b99c93c77fbcce3f236d8bcae32e2c81bdd4b8ce7726ea21a" },
                { "ca", "ebf1cbdd3025ee70c34e644277cbfca6e2601b4639d77c2ec0e3c545f6d0935a251c663d3f2777c2a146cc4e3efaf1a4f7d85d84001bd428cef1ec6232550fd8" },
                { "cak", "eb3be25a6b7ef4561c5e901537654c78399766e668a061ea0d97fbc6c957782691ba295e04b140993b43a97148e67f16213e73fc33afcdcf82c1163d879d2759" },
                { "cs", "69e8fc89d23c11f77600c827e8d6bd29b7294f1f96d164cba06d753aa13a2fa58468571ef0b4bc91c4eace9056ebb1ad181752ee8fdcb4b25c6955e894194d94" },
                { "cy", "7af96f7a3341569925a92b3704bf76913e10aa16de02795d5d827dcee6bff92e52a4417a0c4a67a34a352de2e3bc50fa65f9ba38bc96ae6173453efe4b7d1943" },
                { "da", "c42a14a4122662cb95424b9646b41a9c60d95f1289a27afdf4eeb684408b18a98f73e6ad2b9d22715697adc41031cf30c09e02106e57786decbf2955c086815a" },
                { "de", "2087c2c3dd94dec41af8d19900ea1ad29ffd23ce9e5f1d642babc1d0a31ca37c295131276bbe2da6fa97d7ad7a3a5fba4ff8349c1da63fab44c41950dd69922a" },
                { "dsb", "6d3b8ea1ccc265e373ac8981b300ee5fa77cee8987592edf0c3b72f2a809455403bbfe0e4b95c50240d905be3e4474dba07a07b68d56226ad30696c1533fd6e7" },
                { "el", "15e84ed795cf01a8605794f8440c4ddbf952b056ef8a2d39a7c57e111bb045d90be3c46cbeac93b906fdfdc96038e46d3e60b2c819a0cf91cc1f41f940d8eeec" },
                { "en-CA", "7935668162fdde29e792f72d687aaaf56337765a16bf4e5f23acb5700c8a725f7a534559d3fc9252f829b7608c4b79df950ec0277b52ab6ae8aa89b2d6346a26" },
                { "en-GB", "b189742f4b6923d8708fdebff096c62e707c9b3815a152a9c12e3b032045d6c81d0530d6a0174d9c2bfa3132120fe30834caa2de7ebb40a7f2e9761353d73bde" },
                { "en-US", "fd0ea2b5e85800fa17d3803506a4a83405ccf06559beb275f7be1b6acfa4996358c9f36c7e34b57686ca5e804c6ab839969d153186dbd7370de2611316c45e24" },
                { "eo", "b341350c2e0f42bfe48c99326593e2bc7a6f02d1f818778bd765c837e3fd78a1c14e6b5e0b0a3e9cb98af9325c48fc4a4b4af26a67beaa65449d6b6e062bc11f" },
                { "es-AR", "3bd25b39a4ee2881ff43577973a859d1aae9856425454a64aeb55e52b69cb6842f8e376dae0ba54369001599b1bf6f04a15cc96b5c55a9fa634b05d324c7469b" },
                { "es-CL", "1a7a54681ffa35653187b4ea0849b0018380eb3979cd2439ef6299eb7f91db48499c2d2906016e218c38684726da6edadf10289f862997fc8898bea8395ac5e1" },
                { "es-ES", "c77de132c9046b0c28908632207f065adcc1ed03aa130d743ccd493bd0469dc6e6b74b969370e0385f20a5e72b00661d38196c35630db3161911ea3dffbc4817" },
                { "es-MX", "8aeccf0076f2b8c632b4b2ce7dad256ac27d35e54df3a3161d30aaeaa0b764dcfd6f311c0391b8ab936abe4ea6b9ce35083849c0b4c7b42b58eaa323dcabc5ee" },
                { "et", "5dd874a60b5618364b4fce2def078805cb7561f904eb45bd07aef60d785c19814b43df85e00cd634b3ba12a11e0dacbec78737a7d37e15c1253370e53cf7a3d9" },
                { "eu", "48a9bbfee578e564c8a304a5239ad6755fb6879deb82140d647178a071f0c79059b4918a070296e9a81effa3ffb2ce0ab0da5cd7c597d895e97da43967473338" },
                { "fa", "57db4ad6fb03b08ef6b158888baf4ced40b57e19fcdbbfc2a4c59a0065c05a4eeff8df34f97d44a74899f661aa43d0dbd8c76a7633a8b352aff5312d2d8cfaae" },
                { "ff", "37b823281de62ebcac2155e9a2e220e53b12e8548ff4575356b55a43d54d60c005828d228a97ed280526520e24d084474662c32541f37a10bcd5f26ec0514c65" },
                { "fi", "47385bb21bffc64d0f0957e78560b5e0e990884bf117d41632f6ac10e03185a7b8ff18ff886e9df216aa9359a290832d4525c358474122aa1bf598ca3c140380" },
                { "fr", "070bcac6c6855ff8f847f0b00f65780085b332e34066d1b86ce66d440c3f57bb48160cf1112af9833308b592da7637a9caecf877a0680fe9aca592191457b265" },
                { "fur", "7beae5ccfa715157de6b1113927db86ab57038f04015940621ccb51cff195345f36deb11176bbe9164acf221ca81449aedb559764a4c05e968a1ac6f477e1c87" },
                { "fy-NL", "cc6f06e8a254e4e6c45d2e638bc6f9ab80a17fd5a98cb15acea2ae4f980fc369931f65143a0368de54bdc1f43b6111d14da20f8654b58b263962dc4cdf782afa" },
                { "ga-IE", "1af659420e9a4cbb75a2903b14df7443f24ec8582299b6e6f56e09413425e552003cdb6eddab7bf31a8eb63831ef8c36e6c28fdb856aa461712303b232a8dc96" },
                { "gd", "c7aed5c75c2d7b0ae620b3c49075281ffd0d645f249e8494b9ffe86495092d9e78369fbeda1666cbb20f88cc8b273fd11df88cb8c4de8f3826a400a677477f94" },
                { "gl", "edbe0c3b3fa5d959be9e508e1c17c3922eb5ab32a50f137e37b9acbf04205157f3c36938fd27ca5094532530d736885fce5a01cf48f71c08671a2ed25b9f8cef" },
                { "gn", "e6e574b433708277f571374c3879c25e0e0827fd9d89fcb1e37d4bbf795c4c324f0326be4eb84d695b07762bb1b4270a584e6202e5ffb0fc25b23dc42fb6bd3e" },
                { "gu-IN", "ce34985cb2caf315732d8a135bc3c78ce55cadd82c10f7a42644d2083b1494d57eb466c988b59db63670828208c77992fea36b3cad3d13ce8ca118028665d04f" },
                { "he", "1a3daaac6b2c3cfb362db83127f3c3e829c10fa90f9989cfbddc41baaf43ef3b5005ed9f947ce81fe6b83b3eeb8a0027eb403ea68fea03e68153fe61bf98eeb7" },
                { "hi-IN", "79619d0e50f7510e4473be90d050f4cac3d2328e21efc60421a125ca59311048c0c38f0c28132ef66d623ab65ba6594eb77861094e7697a6a71585c9c2315b64" },
                { "hr", "5e3e19076fea3b6cbde36a5586de94f5707b6aae2ec762534103e3a26f04fa19919d06b7bb5c5d9173096e292828088299bf51ff1aba3811251724ef8ccbaf1b" },
                { "hsb", "0d461eba98e815cb79f8202872214142e372b528bd65780cf094158be720a796e255b4bc676bf961f5a10cd79b06b554b79672c6b1c6b1225677febba2dec82f" },
                { "hu", "213567541bd2d988412e6108191e842bbc06ae00a7821114e3766c5ab8309e075211e5280b0abff8878d53b112e185a70f632ae658097d640fa63ac80810c076" },
                { "hy-AM", "df5fbdf687b81fb8d96253ef016b577c59bf545cd3dd9e7e88d2f586ea28163ba2b61414d3815b865bb97d4fbe3023a195009f2f815e74af9c2806305f8f7384" },
                { "ia", "1ba23280dc4fa880019518253a6edb0f5098b23759b26fb99b5872b8af6aefa2576a0b283ba355b73a440bcc436f956e8329a1bfe5588e47b7158c615f294cbc" },
                { "id", "c8e52399c502eeb2a886f43b42b94e984e9b5ef2d3e3b757e309529a2928e6e364b9d66bcc74a25181e19823cdf70dd569a14bff191ecd504109e691152d18d5" },
                { "is", "f74746575d33125c2a464be369adbb913ab37a6433fc9d5a9b03cd3cec477ac6c3b38be62762dcdedfa10c530718fa83ab0bae60854c843bb3453c4965bae599" },
                { "it", "50461e63b8a9d2011e3501322d3d8e292374bdd1b4c41ab5e98bf55b4b33f1887bd6362df14b7eedced32f353bb57ede36d78835c4511152e85236a5f1433cfc" },
                { "ja", "822fc6c0c8ccb0b789de2146ffec789eb6e377de80415a492a4e4dd570dc69c1e7e5f22a63462c4c57443d6ab4fa44a9b815f970f85b1a0ec9269b4265d762ab" },
                { "ka", "ab6d8a8af8668ab5a9110b523095bc3a754428a4002c74f5a0b11617d5ec13330b1dae92bc14cb7f96ca79882b2024800267b0fdeec56da97a2a68c1a285d150" },
                { "kab", "8fec4b7e2ddee56d316494efadb7095d493a1361cbff0ffd12b5a8ca00a224b80d4524a3abf9ef81bdbcd27ab82375ef6cbb01709a18d734ff3b1ab54e2ff5ff" },
                { "kk", "29ec26090c6cecccfd89e80347591049ec97db27130ebc1f3b2ca54090ad39346791d9366daa3693c9e43a696880133576b87bba82d7251d75607e9ecbb3f2af" },
                { "km", "bcfda60ab5fc86b97a22e7865ebcee0cca91ac5fb4c7d65c1cc5eff0e1a74f6590e8c037486ed01583e741961de0aa125d682f0f34f44fd21e0795eb5a3e3ca2" },
                { "kn", "0435c9259dbd7d1e746bcfb2afcf873879460eb8adb4849ab41c0a4c25debb8a12c761ccaeb48a855e30768fb15bada9958857d641ffa231da9139261e2a2e36" },
                { "ko", "917f8c1b09442756cebe6ed8776f17a4ba20f23b2c20fff97104775eac2180d585ddf5df5e2529fe5d281a3486a3b262bc38fa1cea08f32e31461b1aa0c4fc87" },
                { "lij", "a33787fa3a4b9e7f59238468bfd8186ab8285c63984943f2697caacab9b6206d7486f6daab3220314ee34ad510372a1753192a0cfe9ebd9a67a7735c0c19c39e" },
                { "lt", "ee9379466f65cabe9fe4a3db8418c8feb805e9369096acf76d90cbe85780d24cf424b597edabd6d7241291206f5f4aa8802713bf1fafbc71804ede58978309e8" },
                { "lv", "d953d8eea6be29e72acf92bc8d8add626b2d99f801357469a13ce20a60db46d7e7b58aaec75f853f59854481dbe2b469322774162d6da7c757e2f06eeac36b7f" },
                { "mk", "331c64f1a5bee1f7ba7b96a6e017178f98045b6c7c6f3d8a2a5877ba9d83db9a4066aaad433791aa2022ed7d9ccbb977b0be39f6c1841d31c4c8d195cba00c75" },
                { "mr", "1783bc17c0fc34f173966f997e122bcd7fe90a61ceedf0a6b4a2126878c7726116ea476b98dc16e282edaa6be0865cf7a7f47ac94da29760046ee3b2f662cee3" },
                { "ms", "d3e294577fbfc9d9e7643c51b320aac64615fc256eed2a428a5fd095dbbbbf0ee75a7beb815de0be4f04c568965dfd23deead304eafb4f5a8cc3d145bb7c5eaa" },
                { "my", "26147e2279bc1602b8549a68033ee82213fd806492670ccafea6a3f8b63962b287407cde45877e461e6649a88069f1917c1e6fcace05e78496eee8d286c0f459" },
                { "nb-NO", "2325891043aee1d0d5f6b5cd156759ebcad15ccbefd002a677771a3d182b7e3a0a2a299bf9132cb99dccd915e462c96a2215f52246bdb4ed71fa4909b618fc1b" },
                { "ne-NP", "2a0371b2ac65f95df6b3752c551b8e4b0f8aa6fd960ab4d9012750d8fb717bb991ec51945c2f6221e063020322048960740e785a4010eca8a324bd8f0567182e" },
                { "nl", "6f6640e9ebd1dc35e38e89b254a2144300ef067bf74ad1ef8239f4ae7366110d0ed5f8a555b9998bcf38895c1e906a856bb2ef51a4fabed087f73f0c9e7b4b31" },
                { "nn-NO", "80beb23956aac843795b2f2671d8d38c279b63a60b05e5d2a6a6fa4a246e20122f789a189ca887219ad8307ef3478443262277c48c91cb360248f3744e546bdb" },
                { "oc", "4b6c8416f173d8d3f6eefeedea8ec5704a9d26cb8523624b770685c032c984343b1b2a151ae96f0ec0a5816ae92b03a42f71df66507601c1e3af01141ea0cb5a" },
                { "pa-IN", "6f6fb8edc3a36c8ab7a1e718124e9a55ea18dc94703e39107bf6181c32fa0a5a444e71142bed2e1a8d6e4f8d3e91810b464aefa4d0de8f26519bc811f93e28fc" },
                { "pl", "0d95ffa9ce5b3536ae2bc21ba4a0e85fd8aba31f00848a42a1ed37d2d1bccb9eecdafe1f5560a329410a99b439eb1b0b601ac6c29c299ff0c32a4c90b977760e" },
                { "pt-BR", "aae396fc99641cf8f62e755f8a70988d3780d18040b2399aa45e2686f16297d3831e70bb91f8b741d9fa29a4e9d8e8a80643d70868e192b4f5c9c65595178a08" },
                { "pt-PT", "de5c6c651988024e05da12e970fba15f7b03adc1ea161f34ce70cad0bdb954b3a811309763b5c7da43e09dc14a96be68792b93936d769129c9c999162a3c29de" },
                { "rm", "02911629e8a2538b2532f9a0dd1e3c83949f09f886f5f48ac3fbbcc843597b1657ea7bb250dc8535598da07147c324f7d4126653ac1cee196bdb3fcc31c4a87a" },
                { "ro", "762ce255e793dcf00f5d4011e1df69ed92d8d115d59e6207a6548c296aacaad0ccaa3b9d9d035236453083e8ffbab773c83a45ca40466d00f03bab8a598796c6" },
                { "ru", "b872890193ce4a92c9eec4b51aea25bf26f8d2892df5f074fa274bdc9d23d447462fa9b3b71c1ea51afc7f1f581db0ab1a6dd8bb94e12744e97d0ca7a2fc01f1" },
                { "sat", "84bfc753f3979e377cae8720b7e964bb7f6a995ed578958fcc9d7a588f844231fede80d609d0791cec6c4594134660976b239de9c2e087d0e956565c24c54d45" },
                { "sc", "52aed178db7594835d8d2d0affc6f4baab56763ea74beb0af86e352d395059b6fc965cc6db06c57cf974b157c5bd7b8d1e5b36662aea85419706521747691cb9" },
                { "sco", "302341f20e8e9bb5e923dad2bbe87372155859a57882d1fc53ff0063a89fbd6983608add71d794839fff083535142c1d42d4c2d1c9e888247c2ab73096d9dec1" },
                { "si", "1a372e88a16dbea9d44df706bb56b231af89123a2113cb35ec93a3e0af6231223d99b23ef77cbf29fcf36f0b8e98d79e3e77387f104802761d912eae7b4e96b5" },
                { "sk", "c21a4bb3ebf8c17c5103d452740c73f761f43bbbb249f1f50a59a671fff939bd28b5d10e18ff8813d05232c4ed7a73e732b0cbbfca4c7874d259257f493ecb6a" },
                { "skr", "c157b8295509d98fccb5b36aab4cbca0deb420f76ba2fa7d6a28283df5d5b378a2c4bf1c2588c33d3e4821f6c558fff52da8f1b99954575191bc7d28450c4f30" },
                { "sl", "e1fa62dcfe898dc649734cfdc1ed6863eff5d978e73d62aa527dd571d2db0387ea56c439cb7c459dc2baa030b7856af68e808ffec5b52d7694eaa02abc6b4649" },
                { "son", "66401f54216f73e07578219258edbd93ed2d1d0c7dc109c141699cc0f9c31ea76f119840a9c1d03bcca7e52106d667cf215a659e00d1036fe9879c43bf924d14" },
                { "sq", "16e8508e4e201b7fafdc4720d4eafd2883d6f2af4226a7541a3c916b119b08637836621689c41be66347b7b37ff99381c2206b1ca5bd4857b53be470ffd9e712" },
                { "sr", "3b681045542098c50b14c57cc871707a7c1126a75098eb2c60ad1033cbe5694352232a50f85a40f7339ecf3260932cf068803b8820e585e5b60b094601af883d" },
                { "sv-SE", "06f35aaa32993ad54b991c63f74e92e21ba875a07acef461a2aed39c22f372d6be6c926eaac71a07ef1c208771fe7a602eff906d33b063389d3b13833b615371" },
                { "szl", "6027cddfe6aaf649c9cbab1766c9ed4684940a0c20fe4e54441a3868251e4a69bf618467f1cc04bf3489efed88a0282baae1acc02c8abd3374ce38c5c148e349" },
                { "ta", "2f58b977008cfce8f90913ea6a311dce71feaf54e60f65fff10d9a1b3196f1a0c12a0f4a85b3620bb41a074e61a228800fcedf67cbd7feca11e468c47a3b450f" },
                { "te", "1f26167860e767ebf04edad87857c2739798e0fe1c3ec1566d97e589e9873f0d678c422896737c1af61efd461b30cad2eec4d30d8003110a89615cf1ac0e6720" },
                { "tg", "dd7131db9e29d808844c9c9a6ff166cabc40e93bc3bb6a3616475e3b32dfed674b8f1f11695129774574bc421134c2060c34acb6b12303236a62e809b2044942" },
                { "th", "2464538b3835bdcf9be1d228ff823d5aa5751317a6f87b91e0f1d153afa69ddfc995547e80a421e50808df5b9a7adba2c06e73f52f0eefbe725fb17b7e42dcd3" },
                { "tl", "c3019f5283093dcaf5b7222d07a2ed75445c91ab4b6ae263398b71e1f9cf6c876adec639a7f4e241d2522501b0e323802756750f73cb53ba719ceb687ef83dc8" },
                { "tr", "baf77668b7d02e94d3b1ca4fea1e37d4630eaa132ebb20de0224220b0c89763bd70ec8b85ec8008341527c5b792c2e4f6fc9beceee623edb4ef0473a8b86291c" },
                { "trs", "6a36b7e794db1f77266c850e4e74a6b301b10d8f90046ef4d022833fd4f2623ed147a0a5f019fd4066538caebba780ff8af211854c93949e5f23d797e674028e" },
                { "uk", "db67e4da95c6c7fb2c558b336970d45de1ddf59c3e07f0d87312816cac9966568bb0a49a9a20085d66dc2cf254e4e5f166cedc5866998ffc76be169e0aceac31" },
                { "ur", "9629d4974eceaf877b1aa5f8eb2b176910c64370446e43f85e47bd01f4467a56ed821e1bce859a8363331aa61dc1a61cfe00aff2500fbe2cc38eeb29f873f383" },
                { "uz", "aaadd78e6805d793d74910bbf63527f7201b32dbe598187a505e2db18e09923803bb987eb822ec6cd7c3b3e17b7b3131c0a0b9ac159734f1a0bdd0e2f5530732" },
                { "vi", "900d00f25c96003900741bd7ae6dff707f879b82d0aceb8e24394e0f09d46742a1daac8ffea866d9d597da3cfadb840fc3524db8e1f0f492561143b371bac7d3" },
                { "xh", "16697059066f904ce54d032a64a2bbc3ea390d433212d38a92b21e51398dc3581090fbe97584572b65b35e5cd30b1597045e74d9e85a537c5677eea39822b1b3" },
                { "zh-CN", "decac361569c26811b9a05b1cbedc2a727ce11bc9631f57f56ea685202d85a93625e3948e1623eb4a328956a924f6e816e5b4d85688dc7bea6476d0890bf3977" },
                { "zh-TW", "8a5c3f4e4eafc858c39122dacc483ec7114c47bbdbad3cf8517ca9d12e08bf500fc0067cd6bb14fad8c65b5cbb34ea2692819aeb40b14097f3c21257fbb7a7f3" }
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
            const string knownVersion = "149.0.2";
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
