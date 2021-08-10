/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "92.0b1";

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
            // https://ftp.mozilla.org/pub/devedition/releases/92.0b1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "5ecc81afae95c9d222f56f2cb2e4dfddd54037c69753aed92be5b1f55b96839ade7a2e8fe2d9adf1b5feb07fd45c7c9216fbdbdbf78adad46a912ebf571efac4" },
                { "af", "a4dca91cdbb983dc9b0c7b71d1653429d45bdb5b9b4f7ddb9e59798df32d40e09bf23abdc69d77848c9095e1164ad4fa8eed03a16b9f43dfd451185ed77364d6" },
                { "an", "e039540b08bccf28f2f3843e951b8ce2b5f036804d46108f54ad7900e2824c7c22813407dbf905d0e38fef7813e2563c9860ba3a0e6ef7e662bae95b9da16fe3" },
                { "ar", "338413a73811d0f450b7ca32c4d96cb5beda9e94c3d4a563523d0db83c0e8d69506fb5c037b07589bcab2112b646a26be258aad8b564430aa1b36bb95a8d12f8" },
                { "ast", "3892208b554825e3cf99d9cc04ad23f7f78a9b812610182e1a200899aed1ae47b14a2596cf7001ad56782d93ea331a66524bc7d82455d413aeaa4aa8517c2a9a" },
                { "az", "848b0f3b197bcead3d7ebef9a3ca026054b2dbfc33372e8f562630bb14463cb5a8e8e03476f7d074588f26a95fad741311ee9e29c28afbf0634f500fa2767359" },
                { "be", "a54cab6a2d13f22df61c24d71fac7d3b605aa0ecfef0ea7294efe760d94b73aed8639515823b8ebeafdbb41dd4d083fecccdc5fc7687b510a4180db300ac5ee0" },
                { "bg", "d49c1d693b465cbea6c3a499f5a728db3ebd64d2e757f652a33e964978448c20f7f3cd227adc3054c4e794b290547f193dda93f2f44704348e71672ba18fab9e" },
                { "bn", "bad8332bba4bc9b71a073e7bb20e617bb3e8441bc05124b1cf8f78c750a79d2702cc13a7e5d9cdc4a4307ca49f92136eec809acd7ddb893ee7ed0c7ea7d07dfa" },
                { "br", "acf7c00f785fe8634ff3005a9a9c20c853c1f3645c57f992587146856c2c76e7238abc53e0d42cf7898651b0ee92dd067db6e0619eeefecd86e07f527f3e1cac" },
                { "bs", "cdfc8145a5aa2ec3cc0cd290dcc948c1117517f0cd821106ef0bf60eb8656eb352dc6ae3248cc90dfa81e66eaf5a5681ff12320c74578e155e2da81616d6d3d8" },
                { "ca", "fdd7a537a8a4c0d01c2813bdb9ea2936bb2fb72c1421e48ab88a40bdd2c3564daeac3a5cde2f8cf27ef9227a98191d86fed36fec865d2550b0df5d085e641ee2" },
                { "cak", "6c10cf4ad86b670f85521f7faea24fd072195f216d5dffa42beb6ea1aba7f74edf4b79c2e63481ade1500c824bba5438f01d157a1a0b3f260ef9c04b4f3bfce4" },
                { "cs", "6311e21931d775f899bb8213f98bf8b970c7eb27674394ac3e48e6cce3fd59dcee7fb71f33872ca94cff046c36530fcd57f59f9fff0b08942f3aa5edbf501635" },
                { "cy", "7f92183c10d727e6b2aa5fcee71f2b7b2aee86f34a5f2bd07ce9c0cd74bbd08d03ead5a36e5a11715d6766fe126614a39ebe47903a45f4ba751f69d56e2c9e90" },
                { "da", "2ab7ed994acaf32bd2474f24f5473acfbf38fbc399264b7a9dda7865a305011ad892d74b7e45ead9bb4daf2da1b4f385ab27b86bbe7450404858b83385c8e286" },
                { "de", "3beff8e385695f8a95fd09bff8ff6dccf2fa8e43115d28eefa513650edd2be220f7a5e31aacf32c4dad2ceb3df19009e8d7abd429f1f8bffc5136046f034268f" },
                { "dsb", "8dec060752d0709c897ae537c8ed5e8ee37fd8168bc399751dfa14642aa523d332728a4e0f098d01b3e6d6fac7b3369cbeb9d88a25bb8c2dc5060d8e6a732e7e" },
                { "el", "37342f4b27033ebc05548d5c5f4bfdcaabdfef41ea2bbcfcc9f01de928a7f2cc7c7cd3f7aead0134738cbab40aaf5519aa7e2f9a316db36e38e1fcc1dc5249eb" },
                { "en-CA", "683105374c917e2f7500a853a08119dd14474861ecf27bf20af26b95a473fdbd666bf2d91b3ec3f235f370dbefb5bf1b9ddca05f087efb8417202209c68a1e66" },
                { "en-GB", "13f1386e52b12c9caa2090c2cba98955b05e4ec5b88ccd210a0a2e1109e190d6643cf91fd416cdc63ce448ebc57df2ad9170934f74ba8cfc7b1eaca65f8f73b9" },
                { "en-US", "a1e91b9547882662938acd7c3bd2dd9fb5bec2bf23a1625fb3fe4ecc4136ac3c4584ca28f3b91acd8329105e88c60aaa399d08356f4e9d3efc468ea783c47d0b" },
                { "eo", "2b773f45901dab9e1e813fad67cd2312ebd0eb3151d737d7779c96fd65feb46874335ecd08ade37617b69540d95d095b35eca4d092785dd0d5a16717f6ae0fdc" },
                { "es-AR", "13d812dc350f3a245a6847eb8d525cb65d473a8353848a923e8bd11a7f80552b4e181ec97c9a463f85360ef09af150591c41e75998809c4e0d1b58c20db2423d" },
                { "es-CL", "32255cec0d286f39bfbec200644b8565a5ae4ec9f83bceba52065fc06aa5ccdaf781e0066209e13f904281db75e9210f4819f8d23c2c39d98f28b85ba3f5e285" },
                { "es-ES", "b7f75d264495d39d4a619c55b37f579909efa0ade8b2a86e768ec07c7a720a44877d2bacf99bb995afa2755c984c55c0a837a02780ebb4e65cdb9dc5fc9366ec" },
                { "es-MX", "55b5fdf9f3300c45db4a661a361f767ddfc226eefe8db1664ac960b957c5803c5230f569ec40b5b9d491e782e7ff0428e3ed3188932e81731851f2fbbbc0c88e" },
                { "et", "340c2bbcffbfb9cd8e3e6b6e607678c8ef149c2b3e77c527905a299a9018ab067abab54dc49bfb96cfab713d8e5050abf62f6c67d053e0a1eac7c84517a574c2" },
                { "eu", "046be0d54a4d3f009d99d0dcec4fc7e7f7d0681646e30a7a3278943846915c55345cf6c0a8cb42d3276a0e821a5523e4769d8fcd5f6dfee736b1e5e3faad1d3b" },
                { "fa", "cdac9dac9af8b92b7eab278c45e322f3e704796d9bb4f5d0978a79e5d0a647d61c87935f11de3761b29f293772c9c548832ccaf9a0a0f3c92e3a10fa5c293837" },
                { "ff", "ea039c183ee5a8c04326caeba8eea1bfb2c134f60c69b3fa2a0101708a28fc24fbd580a3fa46148c652d818bfaa038465251b645b261ba375d16bb4ad4c2576c" },
                { "fi", "aa5761ecc935169f5c4a4f7e7d6bf16d52010f8360a2f9560717bf5b01ae2cc597cd96b43aba1b10937b0715fa134c19b01b9fd9851e0b32cd417279af9aeecf" },
                { "fr", "fd89c15bdb171a8ec86af0879e82c6c0b7cb6c7a7056039a1e827049084d9939627f57a5cc164d4c53bfe48b7682347b2ad2985e6cbe3c4ae6fda0d94448add0" },
                { "fy-NL", "31e9b1f667aacb3ea3aa447d8a9509837953b49d30ec8a05123d679269719d8e1b81551562da2180593a4c10773d7c95e917e82763523d6438b30cececcb448c" },
                { "ga-IE", "12eacb5b05602bfe8204ce0563fa601a8b8b02b1b4680facc21ea58231e84fde3c479b0baabcba9fcf95eb301c0d2d8cd1f4f16b95a76ad0dc045cd59049efc5" },
                { "gd", "30cec05f0954c3193734e9f1d81b8369c81b2af6c08bafef1dd9969f2f022417e59fe08867053475e6550bd5ca9b80b272f0b330a075fccff207b9aebe0a95de" },
                { "gl", "c10dbf5567a37a0ad7d77c2c5893097af69a641b6767f5820ed657d1647c7958fe81800ec1c45578ddbbea289a39fcf8c12d0e13b665d4563135a4c32e22cd0b" },
                { "gn", "ee4c50b422a29d2d0719abd01d36ef79b8c2ec41355865758d2e16052d182fcc740026c678ba6f338edbbb158cd4c9681ff7b2c94b79946b77a83369c7a70fcf" },
                { "gu-IN", "18d08adfefd376ca7b40d7cf897027c1f884ecc7b2f9c40d70dd7864c05685b78a92a822b31a581b08fc5aaf897a3e943e5b7d5738499ea9d73ead1de2e8bb68" },
                { "he", "715b7110c373ff5ba177bf6245895f969b0ac0f8ebf18b6b6cde6815dcca6c3ca6d9645f30d30ec29f882677bc2a843bd8a2871be2722d8790a6e461ce66970a" },
                { "hi-IN", "8742657c7d49d4b3e2b723454abc94bfbfd5121fcda00536ba7ae82148b04a3e3bb1ec28d0a25bc92e6e026531a409405e6dbb4198e22f303efcba99a67c4f45" },
                { "hr", "0e4c6957ea1d6a1d32c5e7fcf56d8d7693005a5f703a7fe81be93bd1aa7c3b5225e51b1e505484ae68486585a043a6aaf1e023bd041cc6d34f0562688bc7c436" },
                { "hsb", "f2d345d15f577194a8fc481b612d3be104ce9af60eeecc3fc133ce68da573cea46f2b5832e3be9baa23f9552e6c1663dd26ee99a6f45a0ba896dfc8771ed2613" },
                { "hu", "15c9986f1c4b837e90d7921fb07ccd3545e62dcdf282e45d612017a2e700120ef6e2af7e875bfffa92dec56fc3abbfec228b8bf3b197f5c9eb7d5757910aba41" },
                { "hy-AM", "6eee1da22c9e4000dd49e4c2777a40596d6948feea56ec7b360dd8d9c5bc586b6d538d2b3639d97ad7ff36ea65ca766348fb1d245248a2cdb2ade5b58521ef00" },
                { "ia", "54f8b17aad6046b0b7856b7123509af82a60df03109ed60afcd0781f4321e508645a3cf37ad25e555987e45bf338272be2891883f902665193453ef0608af942" },
                { "id", "40abe3a284067524e0992d0de2279b03185c3b9e78a3198f9886e6996a9b6cd64b42aa747fe325091471e53562e8f11546a646c33ff3e9959054c19b3b2972e0" },
                { "is", "9740f473d1c898ba1b111d2b83d6037a0a14c55bebd89096b03ece4db9803e5b6bb2036c478d2d82ae710ed499b12d2537cded197cf17786ac5601fdb66bce89" },
                { "it", "2900a5ec63a52cf93dc71df3f89286f49b06378607057ba5d133c8ac3c7a98db233c5765368bae76926e152ecaabe34bb670850497e84ab397836c1f68bcf6b2" },
                { "ja", "c98342164c68bb7118b3eba5bb07016f4f9d9e040f669304a3594156d3503ed62e9c07266cd561e4cd4ca37bf4347765ac530e76262d37de058f9004bcfd7ff8" },
                { "ka", "6d86ad33c7b93d2dc435b44fd634e2408daa7ff6aba904b7a18c237367b2264e12d877eae68e4625a65e55ee8e5f3cba3c00504a3978e6ecb1e81a905721de45" },
                { "kab", "922c0bc0784fb5163fd21965ed540ec9722bd93ea6311371b3ae50d82ea8274cfe6ad4f6b78e35ac80b52b19a5dc52c61fc8ca5224b889c5dc114cf95d4ddfb8" },
                { "kk", "6a3f090cf5133fd30d7ccb7bd632d630d3b3e4aff2ef7411540460993c33d63ec983f79e4d748e2e42a49f730f0f329d9fc3a4644a20b6134566bd24085a4232" },
                { "km", "fe5f8af3bb8e0555ea34966742f9f1488af792804c594fae1a3747bc4a647b34a5a7d1b4e13996f8f3059f093ff52fd39185604fb93f0bba418c5e57eaf7aeef" },
                { "kn", "77a79069c7da8a228a607687e7ff1d9a54781acdfb680596a07cd1795330dd43346e5a29d91af88a01c61d85e141e2758dea61d626ce6e67c218b208fc464e7d" },
                { "ko", "f6fa3046334043db0b6350612741b21ea673e5adf5ce549f6803068c35e2adca5a005f71ad57101b80859bd449fa621920bbcb06ace70cc374c6cecf13b0f75d" },
                { "lij", "fad5db15486c32c037d4e84d990a27668b97022ea2d9ee48d8d6e3b671a6570f5e71532515e1ae3eec47f5ab8e085039bee087813d1908798c42ac3b7a441ae9" },
                { "lt", "ffaf229a7f985017c2a37dca6c9ef037cf0b282f2f9b04283a1122ceaa07c2e14b83f0f12e0b680a06b978abad978547f4d6ab343f4d607ca9b07663fe108100" },
                { "lv", "02c78a482d7fa4bed99f0ccbd8f7598dcf5a01d3ad8f6145e19184fd61798d06a007c0b8317272bd03b706559ff417c62c2101fa0f98750bbd242c3e4abcbf60" },
                { "mk", "95b06880c7a729bae32c0af7c727351efd258ebf5d8205f8c50e303ecd0b9616ab11b13e63b9202ba378376c8a84d45cb243eecb0e3b7f3dfd6e2ab40fdaa705" },
                { "mr", "20578a6b6f2b5c7dbe60ada0c35d4594f2fef095ec77ce1ef8267af4724d0a68a8f8365e82326eca798d95fbaf6f3717d454853931fe6b8627a2187cc2ca72a7" },
                { "ms", "e448cfc8c47aaed44d5994249218f3066f96c2e295f687ec5a9e8201e9f934ae589e36054d9d46c1daa0acccafb25f6f2e09d4d6c113a7da6672b1d331663d0d" },
                { "my", "dfccb7ecde6123c1e22ae5bb20a1eb4fc44b6030eef3da0862b2800c1358eb6060af2ed78069cd3fd18f1857675905f774da3f9714837b144caf13d2862af1fb" },
                { "nb-NO", "1fe6f1f227e77c17188fa106a01257171d20ddca3bbfed6a994173cefa9418da9ec7755b35233d0d986bcb780388788485205ae0a37875487bf50843585816cb" },
                { "ne-NP", "fb3a4c87106e4317854e39150ed4ca9ffaaaf850dd27aa1d216567be6d79c0aeb696fc0f34ca7ea63d6c04738685048422eb66dc45cfb8240455b6aa768b418f" },
                { "nl", "be18b716dd487967082b3001bba2d0ed7756e8b90344a50ad699fc06520def528029cc09a50519b7e9ca71a4a8b9082c9b4790ffee3ac888947bb0715d4f111a" },
                { "nn-NO", "7fa91da15e8a84858bb9a07eac89045aa078734840dd4055e462f238cd12cdbb5e7db2e69a8b93dcaa5c7a2dfc5db82f7e153f3af4445cfe657eab66178dd064" },
                { "oc", "156ea3bb59c435cce376af8e0539f6155a728221da5a16e353b1a8960a9b0be04a01badce584a8ec347726aa9bc4b70ab0f6f22b70772a13a2f238cc6d398ace" },
                { "pa-IN", "07e6669a0b1fe03617ce39b08261e6c3ac4ece16a417dc6a0dd340617eb4bfba03931c5c58711d51cd1e59a2de62de4271a6f9e99de7556455b9504c05a5801b" },
                { "pl", "9138fa43991041b80a6c6c96cb8bfd722d38254804959316094a1d6c3479e695a456db9fb15e9a2ec4d78457523a8aa62ac40376dda2fd7600223124fb5b0562" },
                { "pt-BR", "88b2090e1f5c827ef810dfc92bad12ed5e7192cd78b35c3fdf1f080c9262cb033349035c771abb9de17743831cb1c6a108b0341ab2b00b294f024b1dd876dc4d" },
                { "pt-PT", "c10c652a6483fc53c0dc30438f70642f63fd8dd595f8dd2704675eaacbc5352d96656e3f54c7c17cb5f297deb396b04e310abb83f8e510fdbf1ba58a439cfc31" },
                { "rm", "f73d837c568dea2f0ae003a64b546d4e83b4440ad899222c0c0e8e91204b5638fd2d89eb31dd582399f3350cd95b1cc488185895d832dfff9246f5cd2ced9d67" },
                { "ro", "e80595b40b096f1140edb9c8d7fbe78d7630a0c973863cf9af70ae7a50c50070ef3c50d78e4526a4a23f3e5230dd248014998cb54de72235c818047fc9100c87" },
                { "ru", "c31938c83f041bc8235f6e4757f7887a907ff139104c0a1b5dc8d077bd60a1b5e585d039c89bae6234f0f822f5a89b1de2ea75ad4db7cca42f5e1226a6de66a8" },
                { "sco", "2f483c7a2934f79828e1e4715a4fdd65bb9c6fd70fb4270302baed81307f55c55b8a9e7bb48d47ac7387b1105096eb517e597af1cfe9b6f67e34afbe33dfc66f" },
                { "si", "9eff6cf31a5cad264d4d8395df4e7dcc71f611536cd83e08c08917dc7feb5a942fcf7b3a8a0b978c85950d237b755b0ecedd9eebe5416df3a1246e1203170e64" },
                { "sk", "b189d85d01e3385a6f21bbf93ad815cf5ba6d607ff698c34878bbd7b5bdf4a5601ff88eeeeddc881b61b49a3095fd65e00849270fde22744b4a8d5c47de3e746" },
                { "sl", "67a71b0a35b6017575311c9600d6e6b75bd9e6f33092f1aae8d86276b07be5a965d7d444b150f6b6003a1a47fef2694fff3f1bd82c1691f625761953390168f6" },
                { "son", "46dcd9eb86fa5d3230e7dee11b2d873bf22c9e80ee6ac1dbfa3e52def3cc72d41803049d9f959a8efc6b75f0db6245b95fae82ca372c459be9257145cb3e69ba" },
                { "sq", "0562cd385796b71704ab6ceaa2de3e803a3d9593d8a7389f4b9611daa27e914b1ee96d982434a93d04e20e97417bc285dd5482785b5d62b0c810973251307247" },
                { "sr", "1619a25645833f267096e5e8b412f255f8926b2b3e28c06b900674fbfe4b8e49894ee42e999c5d6174cb27dc42670be7b20f2fd84b4e19a38ca98adf64b00239" },
                { "sv-SE", "42cb2b073950459b6b852051607d60d6fc640f087a5dc4af3aca8ccdd25266775f82e9b1c5a56145111a63f237fcbe48c6ce5027f439573e9e6d9b14fb649cae" },
                { "szl", "11e3c8d7c4974adb029de2f6a331bb0349e526b4f7f4342475aad002d175e66b620b8945bb4d5eef2646ae792d635c8294fed0e86a8b7000fee7b7d376b37d8a" },
                { "ta", "c04ee4705f59ee94f9714af640df41c08fceb4e1fde454f457f5cef8780f76112cdbae533228b6cae5f1d5456099ae5daffbe3c7b8d671d529d8a9d346606c63" },
                { "te", "52441f81547a6cfd7c4cd94a8cf848877f249aef96f7cc31f7ba109a48d43cbf7f86b0894615ed1f7c66cadfc3af68460895a50aad21252dcfbb471773346440" },
                { "th", "1f0fc852f1c1f89120a2ea914c84a0513a1c8c3b812506c7d3a62d6a93f3d839fe566418b707edf25c7d938b16a554cf623350918b5fafc0ffdca08eda8a0460" },
                { "tl", "668606eaf08b6330565fd33a36f99b6ee4ff735cc83f86572aa9f7b21489f5beb8d4dbeda752bf27515c46750c4453491f21fc45d48837f304738a24131ba9e4" },
                { "tr", "868503239317b38a62fd23e23d210a27af7a87502d6f611078e5f49f6040dd92c75e7f87815394c2038a37511adc4f5405a607f0fc1942195145496aa6f20693" },
                { "trs", "c06b536cdf0fd0eac643e086a11fafbf3848b685e4a235a1dd8337f5d7cd5414ed8907ce1b823f4b05c1cd6f4f28bf762f73ca5f3a576c8d163f32def785f906" },
                { "uk", "288c626bbf707459077a36e151714592ed8c5f9dee66dced30541020ae486492078f6179312372ae1f03c5a8605e476f2b42b4e788cf879fe86373116deee5e8" },
                { "ur", "101eb801d0a5857ecf3c3282601b8cf54c782a3cab8aa58adc508579fdbc16e364725e63f87bece5ea90ae23c0f74243ae62de5f17c418c834e5a448936974e1" },
                { "uz", "cb2982eed55a14b13f166155c1c30a210927181c98413decc02581aa5ee11073d2c59b984daca45a3d404106aff84408226b9a0afbea2e722d18054cb348abff" },
                { "vi", "c68ee87eb27a6aab8be219403ba42525585d10c1482582351e79dfabc0c5ae279847222d9f6868a2770fbf514d8dbfd87e17d97e959a09f0cc726b76fbdaee6a" },
                { "xh", "f1d12de70ed38f06ac0e8923549548c406af12bf04873100302711f31fd0cae05182e9b3c915aa0c7a35abcb8f2241bccd1aae4dd5d9d64969a6291c64910ecb" },
                { "zh-CN", "a12c79124bed5d582cef3f71c5b6e760c1dd6f8022ca5d05d93567c224df1278854c405b2b31354d744cdfdc16259c2fdd0bdb68275bae4e531284a86697fc56" },
                { "zh-TW", "1e479dbf10a7f3af6dea812521b63875ced3497537a92acf0e89d68f14322be520d9a86ea9eb3266223f314ecfeeac825335d77230efe2387ef94b9b4de17741" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/92.0b1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "403a5a8c0682623882e7b0d5e3c1cfc2449cabea3e8124f64069511255efc54c472864de322b0675f913b9cadc8c3e0888c7d04dd1b7e8968d15d04a02cdac36" },
                { "af", "272a9a22fed514c0b73d5119a0f4488da54a5047612977bc3a9327622f276964d5ce56bfedcef1bf3da59a49cd07d0c3b0873292573e2325be4608810e975ada" },
                { "an", "41e99a3ccd465a1dd5e8c7098edcf40347dc7b390f543ed16fdfe315863883e7060a84132cf567c40494c10ec419482d2628e437cee12920be9d29617f1a2d6a" },
                { "ar", "61ef94bba537831911a25372d4552a78a55319dae723b5892f91479c6f31ea3c78de996f658f2af74da9d89b9763ad239b1e7ac59b5448dd0f4878bd5c6560d6" },
                { "ast", "5714abc010294cd81eafc72766371def6c1a8984c6f3987c107e95c2c435698e2976cf8cd7430d370b7c62d2e178e198c48b937935dae644d46345be3792cb99" },
                { "az", "dc1ff6bbd7fc9006858fff8e112c3937d358894d22d5a576533efbbcf8925a75ff6d37a4d10785ec764bd93efdac46610e0776642c79dd5a153f2179e8b600c7" },
                { "be", "ceb7c873ec61c8b7e1417c68abdbebb595cfc6200e3179f08951e2d7e2f1e655439e3d3d41c33183f39eea939e8c850f2fb060034eded4f6918f79ed8258c9f8" },
                { "bg", "c845cf9d2c18e1ff4182f52a181ac1645f3fd747565d5129dca7ab527baeaa5f58694af6addefd6af26a7b7779d23ee0ee3dec40ad224ecb42f030e180a9ae00" },
                { "bn", "60b249e7d8fd722c41d1de6f60e62869d78647cdd9db87371ba9f22ac4a17b294b0e3304dfa7a7c30c61bbb165f69d904da7a9fcc68561a62bb46f1436416ed2" },
                { "br", "22ea97bedd6c60cda5e7c47c68a68c1bebff2a498e8720a9f9da8776d1e43b43526d11c477a394d3a53953b8a15572677c7b59792feac3bce938eb76118648ed" },
                { "bs", "720bc24ca296d9d059a82bcb047868fefae4273d514c0c202d07ea160bc83e5b7e28b721fbecf1615a300aa5e20767b513a8d80fd2ae9c2a7d9a6df8ce3d2195" },
                { "ca", "59d8d93bc7d20e560aa035c770972f738edd086e8ea5f9987a70cc0271787b911fb04c9c8c96fe516b36782926929c5eaa418d0e31f16833ea9fadb40d934bd0" },
                { "cak", "767ad401ebe6f47b07e9e5915e360f3fc0ab47dec513d53953058c3f9b7b95ebad9381aa9e13a299798e12ddd7fe5cbb01e3b65f97678ba9d3891d80168ab89f" },
                { "cs", "757d5bf675f31b67a121f0a26dd9cc2662b123fe220e1932023a718d0f67788006ceebcc835f81305d315e9d8132b19a0a75aba6a7b81258c3e7ac8e850f3f98" },
                { "cy", "b987a6f39a716825644b52369edd2aeba18fd94e85f953c2d6acbefff61230c76addfdd8dd0679905559677e99d71ccec425dac202b276b6501dcfc3a27d3aba" },
                { "da", "54dfda1605e6d6952b3027c77c42f2907d77b3f76b762df3eb7b91ecc1f6270dcb83315e8197fee1d641b7cba974e2e3e3934be7bbed551bfad9e7b675d126e7" },
                { "de", "409fd8e4c6928527125e4dab6569bb759d70af062fbbe996ac6fa7ca9b84bb5815d5ee24a64c927b0a892ffcaa72eb3d065a4523b49912d5f8c4ae2795c51522" },
                { "dsb", "0d9bc42486a1ea73c394dac457c8cdc369999782c02adbc7fcd9865cc572683d268024491103fd4aa3527ff72668106da2b19a3c91986ecbd8a43f0a1b9c3c8c" },
                { "el", "0aa98bc32fcbccecca0ec06c6d366af867f977e017df000a7293012bf3dc7d9e8bcf3fc89bf069723ce7ce8543fb109664cadddd51e0109f4d37e216cb053c0f" },
                { "en-CA", "a0d0ade6776cebfef425398d1b4983e7dd45a7b5c5c4bef803e550db47bc315a687bbb4ef3ba9261fcfff0849d33bf5222fe960134e6d09987c1922ed66b4382" },
                { "en-GB", "19a448aaeb492d08e2182eb3950badc99178e36388b2786941df412eadd2cb8ae3891162139153e32bad1480839e3f7bfc4e3dc28d5b6deff0853e68aa856c46" },
                { "en-US", "d2ae8afee5561b75f12b0ba293d051b910c4bae2b8c28106e044049e8174ee632055595e3633323c2556b21e602ed947a4ce7318f98a41db3ba88739fe5c479b" },
                { "eo", "9da2791bd84c3846593d9189d7120c04d98b878bdf634345d940356435aa5e896e723651b81cd9e2a927e4fe0e930b5ea83a7d3a9ab86f0d556f48d3109f9a9b" },
                { "es-AR", "c6beccde245a227ea7017a60fcd218166c3f3597c0b0aa68c7c96d64126f9764d6a23d60ec34444bd7bd32422538a21f1cf9eb7013d9767a65de09b53f6262fc" },
                { "es-CL", "5e249ea459bd037915b7938b72382ee2cbfdbee7d58cbf17b772a32c11ee9292356d499c410937bb9093fa9e22d38515448076d69c10251f067d5c48d182ba0f" },
                { "es-ES", "29870a9748c585e0ef328e3d5540c7aa45052ac28b1537d30769e96a47e4caaacc3697fa08abcb7e90dc5f0781238268087ae378cb3b238c42b113994f4b5612" },
                { "es-MX", "713be21c577356cab8b9a29fc5f3386d4abfa53d8940b46e549dba8f2d071e07880680fc6b164aa9ac422ba1a0533bcbd91f9fb83ff7f54cc29a993489109312" },
                { "et", "6ced507bf318ab629944961e34572cde0fd5664451fcae7f5e4ef07f6cc506e09bec01bb0a667a7085472751fc95620dce6b3ba69363e7da6424581c0e64cfe7" },
                { "eu", "8fca847bb97556aae4a83ccd17083a1b3dce11b2aed3c5b5799f245c4dd879588077ec5e3454501de17f79c39f7b69a42d95791fe93642eb18a68d01d9527492" },
                { "fa", "f409421c48debc4f25fa9c41d7bcc8fd9ebbaa68d897e0eab005428074d16757be6f9af038f25263804155c616fd4b0a0da012ff4ae59d22ea432e3247c0fe85" },
                { "ff", "e60db51b3c25b20f8960bb278ba41fdc7e1161f3e3ae1994d4ce57d3238668af5b890dfbff9f86a1b8cf3f632720d92d0868d6a62b2109c733ee0bc7974c63fb" },
                { "fi", "c6b229e3780fb3b6cb8405183a4e45a0c45a81c3b9213faa57bca1c5e22c7f093fc7184fd9e8c1b6f584d2e511f631e108b3031f3d4920c43a0d73b436c63a3f" },
                { "fr", "33ca0c20bdb2f8eb20ebbc53db319453fe726742dde065925ebfc5fcecf543d1bcf3b34c817f56fbf486e3f3297289ec6ceff87ec9196d1d8088a51cd3b5b6a4" },
                { "fy-NL", "9a11559db3e9511459b09f3409f6c2efbe3e79c5a50a800d92a40d0f0ca82e4479207ef726743df88c56e0e00635266bc81996e3c61367cc3325ea5bb8706a96" },
                { "ga-IE", "e6c8fc886e761ba63eea370bf646c36f7ddc551fe26098f59b4310672ec97e841068ad1184dac3b8744a1c8b45840b41a2b51885254be8e800e9707712d378e1" },
                { "gd", "099af3ed37fb468f5fc4f6e6177c2b871885590e420246d82108c4a464b05da79ff7f249a37bb2ab4fcd22856c58fe49c301ce10e9fb65e058ee52cdeb7318c3" },
                { "gl", "20d45afbc78bbb0b9576eacf4059f503795706ad1aa48606ebfecf297068531c12b1ef3696c373073f054970835cef338e08278ee2db12d8c6a5090dfe7fe7ed" },
                { "gn", "cd8ec09300cfd5232674d69f2213abf911893852ba8da346e3f7dc4fe1653bdb2085de438e28cb6ba6227906486121496d7aa60c27979c95cf4870c257d9c931" },
                { "gu-IN", "6364c32742ec9a1e827446a2750a666a4a5a9280980c6d02e6855fe52ab7aa3e7cc8ec9cf362a8a2d29a8289415c540afc38587b471b81a930ed11e0d2e3f8cd" },
                { "he", "3f88dce8869008816c8e7a7a0b7550428b2d2a4526b4d0bec1b956bc12c15c6d32580a7188b165bc4c1f7a72b02ce8a882d0586e7ce500d8ab8ac9714adb42b0" },
                { "hi-IN", "b3285ed128387e5eaf27e5fe5b58e033ad282bd166f6ee15d6be3d56a300bd6f261b787950842c8bd69d98fede6945e3fbc5477e2a2ee432f4de7f34bf5f9235" },
                { "hr", "07afc3933d5a78f420c40530f56c3518d43df7c2f8a4dd69d12c37fc75f01c8d4825f5639643d4c08c2236e93fd031f086023103fcd17c973a641a5839267342" },
                { "hsb", "8e44b4e26ef29b5d363e365c8a901cb3d50e2a18223cea38e007fee08e645568572b3cf7ce7009ccf6521670accb1ec88ce1ea6149662b60446b26e67cb03cf9" },
                { "hu", "728aee3984e613b99236aca71f73286e3678b4b128b371867e2dd30a0755ef55d58523b5f5e5c2ad6a77ce05a5ba0fecadd5a563d232987874c05c67800a4180" },
                { "hy-AM", "75917f3a0258444bd2c4dad38353f90ea040bb0f93494b1c95719b2f0c1bf224587662077f3ccb278a2e5f2a996190000fca866ba6e28cf78b6ca1986e1688da" },
                { "ia", "ce4f84ba798d809a3875a66839661399be962b1d5f53aac979e05ecee00bcc1825ce9030650cb3bdefe346862ea3deb8cafa723934384f3db15c5b0b8c7de54d" },
                { "id", "bb12911ca6cc2ea4d0cfb2f5a945be44d43d00e09066faff1b3feded570dfeefe4f46ca3266d2b33a7f6fcaa1c0dc0447ed7db924568f05b988f09b9976cb63e" },
                { "is", "f1fcea79d49ab505831cf31875688802ac811586c9264949bb226c1db5d29830ac061af45d32ca648fb6acc5d85ac89bf92b0b58c4a3dacf60a41da82be6d1a5" },
                { "it", "df40185f59aa7c57766789c7b5fd42681a3223e193b0b82261a16a7b92728f53160ab2afe354bceb0503b343cec47fbd894c19dd9adbcb7cef3ec14a101839cf" },
                { "ja", "2880bbef2b4d0f11d13591d5c7d75db6eaefcc0bb54863abfd0f3a8417c1b86d84fca954ace9870aa7a4a604c305f9725b06e1e8caab4cafeb5667a541efb85b" },
                { "ka", "97c5385a2d691641cd82b81b1f52a9cd694ce8c84131a83e65de87e09df90194f9b45bccf0eb2acd75e57ba8b6b70730e8ad1cbd14d7bb68d46d2b5fe147ac4d" },
                { "kab", "2c440cfba1483a8c90c498ffcaf26c1d6e69046ce3f1b1ab81218fe615658e2334a092b05e118e644dbcc4433800b8fd6c0050d982948f90631b386c4a5aa09f" },
                { "kk", "59b1cfa17e606dce27a5b64327795c42928263a04f6c3b9900baceaea09cc3d3e09ef1b93b5cfb7689f42c32dc7332b47edbe6d8e984d0c3c7c2d3dc1989c4c1" },
                { "km", "59eb60eabd09faa0ad1c61c799b7cab82137f622c587ad7a69114ef3eb2ac967fabd643440c07820dc9f4f79b7e040d949537d6edfa19a25b5358473fcd5701a" },
                { "kn", "a5c5b15e6326a9b44289cb008181eaa8c2aa0d922e9b3c19806ebce8228de0c94833095b2206720d19d0260931abe15bd4b60b94b6bb09a71e48fb3bd32c7984" },
                { "ko", "3948ceeac8abff5eff174e74a27a14fe9ab734e3e8a42b01191644ea55836880cdb537451a18434bb48ecab22ebad9fa0da2f88227fdeb14ee42ca56b22ad64d" },
                { "lij", "c8e2ed876eb3e32a0475783b96acf81322e4be1eecd7b23f8a4eaa8a40baddb17fc6fdb4c8237247681467fc035dc42e971d1a640e9ebbbcb342388a814907b8" },
                { "lt", "75a46b86640e491777743e3ddd1ae2175382eca9a0bef9d6c52fc50b66e91b6e9bd4919421585f47863a81ac35c94b8d2d326bac8fc0b8b38fa9ddba349b9455" },
                { "lv", "a5eb5e1325dd8e879aeb663f5b92e6ccfee17d362cbb4f7857df1b1ecf7dfb9d01aa151b0b5d07aa34898750f6b36ae8247c3ce829be8c73e046ceb167336057" },
                { "mk", "119859071b3672605b7d2146fc6e84cba9eb42f6c71a9d5be865f30d1595505d2d0b4cc570d00b8f48e78107afe82a7cf2ad23293c589f9759b52f3ff42310ce" },
                { "mr", "2d4f1666574326f570068d1aa1c2f370b17a9c69fc635a9f5e3d1fcb058d3edf5f497d67b634d22bd416ab00bf7cfa7c6284dafc721449f05e120d925458a8ff" },
                { "ms", "d8ee6707a81eefb3e08fe64c9a552392ef81cb137e6fe80131c33464371f74206a51f7093f45766d2756b8ff2c444d004649ace70a2d364d0b7b34ced27fba46" },
                { "my", "042f28b0067eb544562ad95b6de957352f324e74e3beee3d0425aa3e812d877546ee622cdc3ac8d822f8663fb9704d41d7c280804b16837c9da65cf6dc75a31d" },
                { "nb-NO", "4bed23eb07f7e38ce5f66bb70157a9e2dd7c60d871ff173504ea490e4aa12022df81d38e2c32ac5d511a8f90e495fe63fc70210af76f759ef9ebec115d11736b" },
                { "ne-NP", "b44ec6b057b360d0ff92eed3387c5495c77d4b4eeffac28d29091c3d340e127a00256a511955391b99b71354d6890cdeb2de9b28dac034f380fc715e3e3eb5b6" },
                { "nl", "ee54cc4f5aaf46e797d4b2e3219dfbc83fc961be0e68d37fd38724cb893dcf7d0ccacd989976e625f6c1665fd1d2ff5e5b4cb53f58d1ba73acc476ba948d246d" },
                { "nn-NO", "7dc9916d4a717ec20044aac9aaea290e8761d14613798abfbf57d85e93d599f22ccdefd6bed49c237c98cda2241562d823b9de45dbe16eb6524b69541c0277d6" },
                { "oc", "d1ed6207a60fe70577a20d16283636e956f8215d7173dd08c85a83d04c4d3963b7cc4322b50904e15797aa76e571d004f4f034f047c72f74530e2bd547efd391" },
                { "pa-IN", "726cf747a5003d4851927242575e9522c437951dfeb2cd77cce3630ed68c689dd349cf0257484bc4e65b8c8314e80e3eddb4614b9bd92c808bee2b556a69f372" },
                { "pl", "cd4996577f4a920a4c3540dd83587ada9f0dd13cb3b54d698f79510dbf24d79dde436a5cc9ef0db008bc3d6366579e1de1c8a8cb99626b102276261496b8eb20" },
                { "pt-BR", "56e1b122592a0a702c95c50697a0695cf8c5611cb0cc8ac5410e16d5cff2ac9a0f6610b44868dd4688255fef7a756cbeb1bc757d974c1b97ad1bff5602b400a1" },
                { "pt-PT", "11944dec6ea9f6938047c6cfc2192ba8e3955cadd83e4e670b489a1d89299b1370a80ddbb84c06c2ae9ab86b4fb00528e005fe9be0bc3b246c9b59c3625d01ca" },
                { "rm", "50bb03207671239c61234fe48d40445728d8113e560ac64f78a32c2f3b28d4c977e00e4d8ba14bcfdfb7e30de635eb3a5ae96dde08cfc275ff6416b6f3cf84b3" },
                { "ro", "1c724c273dbaa32b024f954bd881d98a0f07d9e93cf108a39caa036db1e64d1c208434da3b7e7ea261034bcb15a5c3522bca805a43932de6c0a4740e1b4209ad" },
                { "ru", "ebf9e62ff0fde1da3d254014accbcbbdfd36ddeec127cce752e4cae50d8eddb4ccb18a60d8c2ac0144863ae5bc227f120e5337dba141a12b0e059b3e4fe98339" },
                { "sco", "69df50a56d112a1f0722bdd3fab2d48d93a5920015fb9b64915bf681599fa54d903e1f915bdf60a7cc3c54abdfff47c3b586ded85e37d7b3cbf67f732691303a" },
                { "si", "d40424ac4e641a311911b8b57f356095994232f25136a4cea35b5f06771b43c7436e7244946060435cc06b2d391b0e212b9efdb1fe65dcc66d0447315b151d50" },
                { "sk", "c7cc741715127207fdfb0201f5033d1a7b687a67ef24ef11c155ae01cf09dc76f7e1f85c7e839e626a71a7e8846a68529cc4a547d879d82fb51d9ca088460be2" },
                { "sl", "bd67e4025e4a907ac3b1205f8ea047f2942f373ce355b5a515ac88c9cbeeed142a0f21b1cb1ff3f16b8a2b11bd4860aa44e7c19ff4ccc90c49b59915ba6b5e0d" },
                { "son", "46ab15658b010079bd599c0a8a789494ea2803edf8b883facb18bfb5f473d29132a6eee0bae3563f7ffa35821ea1a19e91ff6cb9a7e59f489b5da20995b834e4" },
                { "sq", "527f249bb2ba677f0afd58306a872f6d6ddabba593be5f3a0e6dc5fd150031d339717711dbee51985fe2b8a34251d1e858e9017968425dcad810b2a674c7b1fe" },
                { "sr", "f7e59d2eb7b77583d38afc81755762fcd3c1712b8d9ab7a2bd05e103a1937238b603f8e376f4492597ab8615237b988324f08b48b47e2b2650d064a2752279dd" },
                { "sv-SE", "06a0916ca6b288973150d9150ef3e195e495fb7cfe5a586fa0f9f6e9eac8458d4b318598e3046679680a62ba72929596e4da3328bce3dbbe30c5c3cc7d8c02f4" },
                { "szl", "d8e7c397d593201acfd0a0064363cd8bd8ce6d842db90253adb296a987a5fb2a72b6694523a3ec66a1648f25d44abe6597a7de93c0d23236f60070bb1af353da" },
                { "ta", "1a85e97e7b87ebbb165efb88fa065546a71a310445224331b7d77d62b7d3423fe40c663d0528acb0eb560457b10039c056791c40b49121963fe3744682ba6f91" },
                { "te", "9d00a89f85783893389ebbd219f24352f65d223c23f86bfd6f9e03d381eb3e03bb5543975e5f015fd281d8fd09baa61335c651988b32c3b24548e2727d5df295" },
                { "th", "f86c6429fdbcde7df2ed1cf9e0b929d0c7a8f7ff680c30b437f659e36c0dfba68fefcec40ef02b0644f1365fc49429430ed91b5ead4b3a1a125e27ecc2d110a0" },
                { "tl", "1988baa84f305039e69d3a25aaffd8e4027af968a16be119046504946920eb2dbde58a6d3f6336479777ca0995248f12213d3954c0f2401280f374a89498b206" },
                { "tr", "57d492a510e55754865ca85d0777a6a36754d91fe1e7f6ddd04e7c2641d997cc0967b01a6cefbd6ae32747461ea8ca1aa7e0796df5cf869cd603cc5e45d3e220" },
                { "trs", "d96f4c3488d97f6c3493141d853c1e750e3b8c84198e002d1f154ddf850299c664cec160926f7a5c2ae6c21a81eba0e37f813a566f32f74291ad847dd0dabfed" },
                { "uk", "a80624707f9d339d4bd7b18543e93d3c0a0571ab97850c95eea9fe9e98bc18de187921d10a08b44e956a647c2d596d555c5bae42cc62b91f11a1ee7ef7d2c3aa" },
                { "ur", "7c8f05e3a7c9ce441cf3cf01c1d0ed42fe4e2b5ea757d17a829d197d4a0c1dea214535dbffbc1bd1abd92a0fe2368641f1bba788ca31f0fb21963fa3e002092a" },
                { "uz", "83efb90590576d7798bdebfbe52a98709191a211ce5667ae1109b96044832aa0c31b71f0877a71dcd20c46450c5b31bc741e2147cc01ca7917710b738424eeb4" },
                { "vi", "514c9c7b02f8107d0665faf7ae1e1e140811af80ccca4d56024341d066e76ba4f86cb807169c70b67266e1b36380aba838da48484cc09b5064dfef4c32b04d4f" },
                { "xh", "b5d628c02c115add04fae31f2dd1a35d769cf1a91af0bd7c8a23e7b57dfcbe1fa52b279fcae97498ae54fa457681f8a62fe774d0920f87557e838de7e78ddbfd" },
                { "zh-CN", "f341dae705e0cccaa65159fbf005224b629fafe66baaa81f3f41eb4cf0e4eff68a89a0665cfa3b339253d6dce83f278cf9aaec2314c65fa5a9c0f9d22d3eebe1" },
                { "zh-TW", "8cfd1711b4978a88ecc5a4c37842234299c24f889e42b83680495a218dbd0c04c2cd59ac4773683ca6a97786eb6ca826269e28aedbfd06f09f6238b4a666226c" }
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
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
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
