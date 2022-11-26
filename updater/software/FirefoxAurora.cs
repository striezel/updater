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
        private const string currentVersion = "108.0b6";

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
            // https://ftp.mozilla.org/pub/devedition/releases/108.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "36726d17a152c4d94ab27c82640c016747ca7333b0381eaa80dfd408f5cf8d3d5d623111d30abb8ee5959ed8761309f5baf1c9fce8a0dd1478f25516fd3b2a0a" },
                { "af", "d551e090a6bd966dcedc2a48b4552c173212d84953e06ca74053ebf5eafe4467fb28f5b51b5b07939b358e64eb55a630745784c560a6a1c37285ce1111b157f5" },
                { "an", "e38cc3f7a901795f237da434c48e298f634983a41bcac86c51d1b989721ab35b88379c5f0ec3c947c14f63ffe28e4340df1ef2081a6305907cdf7e8a77ce13c6" },
                { "ar", "8649832ac4e7d9bd2a0d260f165f530e733a0f4f3c239d6bdc049a8aa607dedd085f01d10e5ab5272ab082876b8f63093365fdbb143afa220e5dc8901d0dd560" },
                { "ast", "c0c6ae6f2ee8ae3961f04abee927d736bfb92b745ea3f9d2228a3950b356abd2b3dc67cfa08f0aa865e2b61b5229e9624279ffa3455a396f9c8ff3cffe6dede6" },
                { "az", "89c26ff6e87e464fd8104e6edaf527076084d0d0c22afde0a1aa0ef507bbb95f84519d73b506c70385f8dd00c5a57256cdba50340a7bc29d56006de14921acff" },
                { "be", "5a27e73fd6eae3fd7af1c5e6a77d5e5f6042a2c4ac04f1c2d958de111d5d90f0af5f9812779963fd6ee4e7433ca44aeea1ac0cc1bdb9420526518f4494857dc4" },
                { "bg", "dcf686ce1660fc05787e3001657e5793fddfb946dd8a71ba6ea650d89d90c71d89e4a65a71186d8e6e94ffb14f5d24b0baef6a05d76a4e14921fbfc0bd5507d1" },
                { "bn", "b2fccadf040eb2ff1db577ca78d9d21a914cb6be9a5cf5e2e0cf8cff9c631a8016feaf6803a82c1717bbcd6e68f126fafe63fdc4e74e961a085f5ac5156311dc" },
                { "br", "a8fc919d2566d5d6bbeb2dff9a9747d28932384f9c5129f6398ee6e2b7559e6533540126366d6dc036782e507b19ccdf41a06a37776637cd394a72ff4dc9b167" },
                { "bs", "67a788cb4abfd2f59ab1ef6fefcebbed9aa8dca3847fc943787767bb91a145b3ad41f1ffca8ab61d24ac8f61498cb7e9dee8d9c15caec793dcb301e2218f5c35" },
                { "ca", "8d07404756d2ac049997e552d16ecd98562fa49b6b0156b010cd87b9230783ed6458dd9125dbbba3467103e89908fad6e29aa23a04921e8e6c2a30abc7ec58b6" },
                { "cak", "63a2e413699812678ab2300ee20447cc87c99a2c6f7a000f38f3d2e7428668a0fbebf15456b6152ac19da0a86df300bebb6ea7893ca6776d03843fedbff116b1" },
                { "cs", "11681a088fb6e6c2f8800b2a4c9c838b67f9fc29bcd9e873f7b411e33598ce53ddd1816eb607ddd74c8c79ce511dacaf93b143677bb63b04496078837536accc" },
                { "cy", "ca6645428b14e08dfcef835a3d70c1e588c74145bc968b9d5077ed3e3cfca83a819e7aa9a1ea97dd259dc5a5c2fa60b1d0413ae9502dbc59bddee120b46aaebf" },
                { "da", "6916960e5f107c5c24659484379d43618fd23e3db3275af5d6cbc5ef4dd914647aada03196cdc6a49c9ba54e9ecbd99ef7fbcc237c95c66efe8dd9e9342be560" },
                { "de", "7ee8e0bca6e8c4e6e3a2999f349e8521d16df0e503ebd8c6bd41e90ab7e315e5d5759a68ed2d9d4f5aaf8c960b4be10283a00ea7cb95f2eb7d756c24a452c646" },
                { "dsb", "aa02bc0288b922375abe5ab6d6d786c814b36817c3256d37fb526fd3d686f6ac0d8e30e58ebc96e1fc3d149897f21c241b91963c8d2507c4bdd0112db354226c" },
                { "el", "ad07f2ded9624e89c06b41278545f4051e9d672f6c8b3dd2c2b147ee19767c623afef6b09c13268f5446a5f10009f578fb8de65bb87a5222a8dec62e7d06f899" },
                { "en-CA", "fc6452e665bfe932d69351c50dbd92eb02b27113c0815c38d4c08a6b20b9cf3cf9aabd3c0eeec8eb345df4e7c15401c61381e616c8fad485714d770185a82df0" },
                { "en-GB", "7df879a69788aaf6bda33c2d7ce6193f192975ade1d8c83bb4b4a425704c0be77e54f0206774a630c290a9f4a10d390d188a5e17299b3c7167678ee7247338ea" },
                { "en-US", "c01c07cc3a0b18fd152461668b42bf68e259ae1492cc1ece171606f573623cffef4c07c7adda6c4059829620cd8677aafaefd7b7aeced825d3e9a3c000aa871f" },
                { "eo", "1872bc2ee3c47e56e0282319bc54030dad7ee771f0dab152a4bd845d545e573ab489242a6eac6f3f251e73eb9cb1f2073e56ca221427c8297e2e59ecb499938b" },
                { "es-AR", "5f0cf9c39f9f089bcdd4eda5d7995ca35faf0c5cab3c9b2ffbe0a8e08c0368bdd56a4947cbe8e818df8e543c62c00539f5eecb4cea2b2de6e4f5f9a2a10ef3e6" },
                { "es-CL", "3e4f9d28be1269a014ab1b43b1971031b39cf7826eb073bc42018cdfc2a5a2f0eea6a6d0442538060b55209abec1d01fb839f6d13f45e1d6c3cf1051dfa23d6f" },
                { "es-ES", "3ff2ee53bd26ca19ea05494a2a23ce0f34fe800fd0ba512bf504dca0d9bcebc7e44855c20e405b0d2a6006ae7e12b66e7651d62f777b5995df1c13c4f7682116" },
                { "es-MX", "55ffd552b6a3da1ae51454fa3dc0912c4e927be117dfc6a35fb0e5d649a75f1ac1f5b514654f79226f36fd8d8c656a3ef47b121ba74885f68e7760e8cae74d9d" },
                { "et", "929a95f49c5283e59e7dc0c82da8100eb2976874aafee3372d84feb14f0595a3d7c375dfc3fa54a2602df160a0860a352803d845e3af69a161f8befc6a807477" },
                { "eu", "c8cb2673d7ab3b618f87677919a25f728a554f9188fa33aea4e74a2a686f774ac584667054ae1a4e1776b5408eafdcc1941d4ac238f7c8df9d6b717378ee888f" },
                { "fa", "81f8fd8140da4ec567a48269b50cc06b6b4e4e34dda7be253166bb0747b8fc445a09e2979a23230b3e560526a57e91dc1ee4be44311c5642f9e582909e5312d7" },
                { "ff", "8ff18eee7f0dfbd554ebded73b02d6aea28164b7b045770531ea87a8a9cec1bd90882bab2241a099988831a1845b9ffc2caaa9f9fa338d9ec81385729c197fcc" },
                { "fi", "d7290ad0068fea06863f91da4fce5a141f8a1d96a05238d44b24bc11645ab66a991513841d29c9768676e0185a2e7f5fa2815f1efa0ad75508c4a91e0e58e06f" },
                { "fr", "5945797429c6ecf73955de8ffca1c3c86827efc8c26534ddd790ec47b93a1fc7f4e49c593624a60b8332e5ee910c4125cabb54b06129e7c2c04435604571ba07" },
                { "fy-NL", "64b0b0077335c7a3f0546385b5d7e0274e7de87f8f383d2ca833e68328e6a28928dc29d772b52fb5b2365dc72c62e413d47deb3123a509f1398af4f3c5492acc" },
                { "ga-IE", "f5bef4408a5474af718775f6fdba128f4387540da86b9ca784fdbf68e3c63fbb0fc459222fe105459a57123d6d6a6caf0a9be73b5a393c6e8b71fdbe1f56775c" },
                { "gd", "e71afa392864689bbc2e76c158693832a6a28b52b79db333bac22da8781ac4a8a2388b398eb44a82d40890b27791b7f425f5306ea47cfcb9b260b1e0604a62df" },
                { "gl", "8ec2cb8e9e93ed7cd444e4a04cdea541548a6009d1fb372e4ad8de457694fa2b41b6123e33b6f51f71c6d7d8ec1eac2e3bc0db769be044bfe0e05abe210300b2" },
                { "gn", "e90b2b131b59c416e09a28804617b20b5360e3f5d4a373ca2a0a726ec2e22939c7e80934a3e25b61155935752848fa4fdbf77f57a6a32217a3330a4230eae080" },
                { "gu-IN", "eaca2288d034acab373ec75aef492e95734844c994234d90b81206c697dd7bd24b1a2b54db3c6c95d0d1cfacd58c835d0a94851de87077d9fe2b7c05c64b5a68" },
                { "he", "a9501a7e2fb2b3e3772dccadc7948f03a807df258c8ec2f10a085fd916597d2ccc797b9cb0145dcb4c068e4f84924b87e44d476d719e1f3d39593b9cdceaa515" },
                { "hi-IN", "4f83511a7d355d7438c5590dccd3f8df7065c75c2fec7fa57e4abf2f49691319edb06cf09e091d73ebeea5bdc1a44dc63727bf57694e8554252a458b4f733de0" },
                { "hr", "fd97dad61a596f617a1af24cdcc63fa5c22c27d82e14cf71e126e563d02d917c0a3f37c2350f284e70b983e4ba7f9386cc5816178e6a7cc73a4d414913d8a4d7" },
                { "hsb", "b5a8728a4eedc207aebbb74157ed6ed18b0859b5388977ed2791f2016429b0892574ff45c89af2981b465e5653a077e935c9a79ef1fb3c02e25968f386dbab09" },
                { "hu", "c47679c48ee294138101b60184d14db7374b82609c1c3f31a2df423a7d5d64452ffb272aa35f9732552cbbcdacf27e686ddd9a8aba4c259897f7ab83feab9e38" },
                { "hy-AM", "4f98d7734a576886a0ac7edf6b15d1a891e87e4cafe8bfb9584bbc62a432f0ea5f58bf99a1e464375c32a9a4fd3d1fdf690682b7e8d5f24b021d43f6bfca7e9b" },
                { "ia", "066a25edd2a36adfb15e0064f56d1151c041b2f7e13bafb7c897475d5702a2d1104cc366175834c3d658bbe6a2440dcf618a67d1fb46e586d3b7ceacfc005152" },
                { "id", "76714555a600e14032824d792799147f522aa200352dc577a4cdf6fc90d506410f8f55aab50e4a5f610cf948b67fcfed3113da4dc431d3b9814cfd8189bffa99" },
                { "is", "3f13e050b8784ffc74244dbc291e800f7fe81eb705c97c5f088ce1943fba61000ff93dad58c9cf0bc9a6f39b58cf0b2c5e2d8d6cb233333a047befbef137c798" },
                { "it", "ff5808119f073a326fa524e260b34ea1255daccfd5490906f9a9b5ad57ae29e165948a950f12b63cd55533aada12191e491429b42722d579d010296205613583" },
                { "ja", "b2c051bcfe9921c9d203f7801190c522a8e8e50673096eec722103e28f2d5f5f6306f60418a3f8d371dece86d56cc390757573ab33c2f1db30fd73cf3133c654" },
                { "ka", "b2883056182b693d9f126828e446dd5e6e2062d645c677aa7f7f7fbbdb9681d46424d76d45823e965638ec46804980bee0515a6cf4d3df388156e68b8ca6e566" },
                { "kab", "a386417156ec64b652765c89bad7cf04d43cc1bfd91f694f66ffdae2d21b257a73d2dedc8a8d4e914153431e3b345201e18685f6567c9dd4cfd3e0a0daf19978" },
                { "kk", "549224b6bb41d6e448fd36ba5eb7c5af8f04010371e754e55a03c7a2a4bf2f5b4cf3991893c8f931917f157db0d66d4ed2b50294fbfb128d29785cc1588d83b7" },
                { "km", "a6568545cde0373b4596fc1d949482ee921a5e8b02728b669dfe317f3851d4e6f22c103deeb9e950a58872d2320b3c5d511d8d521c36abb019df08bc23588d05" },
                { "kn", "2463676e712ab000fa2698cc9e4b9351ac2e9310cfb81a72b2fc9b7aa29afeb4db72999635d01d47755ccedb7a024f97b5c5c2bb0843bed871cc4e7fbc1fb4df" },
                { "ko", "5623a1cd77f8b78bf27e30728bef2ffbcc8864881f29590b613111770faf73bfffc58eeaa4eb400a632480e8cbf4910cf80c453557c88c0a2981bd51a34dc6c0" },
                { "lij", "6d2a1404fb28e6513d590344ed89881661243f2d5551c21a736da833a47ee40c7eceac7ba668a1caab460568b70835ed4ab50b7099e581126199c0932b94a5d8" },
                { "lt", "1bb5ee4d520089a7bc8fc51de5a1eb5a5a307df9d65e4c033d6d1213bfdacf6a414d0b56b58100d5ee55e72ba7c38b53d26f30e22939f561a5a13a13464cdd99" },
                { "lv", "60fd2b34ae4282380e78662f5f2cd4b41452c8f60355a3461ac5567a5156bbc53e79eb6474b01e3f8729a9a4bf81c4601be1a8a2e6cfa3fbda235a374f076c1e" },
                { "mk", "b28decb1eb986f81c3202167fb1cc87ef094840d85aa738a936c239a514ac16ffdd12ce113c99fc425bab2952381cde0509aa0fda79b4274d1a957a5d127e0ac" },
                { "mr", "c0fbdc0a9117ff253a6457f84f5faa0ced9809c1f4a3a88925797b35918cbc0f7fa2e70156d75bba1ccb6339178cc263576f62e19b7e47400914d50aaa3df53c" },
                { "ms", "4f9584edcf1c4bcbae8518237464c6e451c0eda807622e53471ce61fea89127018488da58268de230ef97ac70e9c104c708c3b56ac829501e55fdf1201d330b0" },
                { "my", "1407708f32457c1a3e3002c95818aaa976bdbe0e06d5c84429386f5b19373dd37e12f3cc087666e7c93fb31288873f9b8d7570df188ae68a89faf7c741f799e0" },
                { "nb-NO", "5aad7f1fd26a55e1644a86a200c78abf62484255e1980ee3a7e21fb7dbebe006d5acca49249f28b1712b1c906082495222c49cfd7029fa28dc28dcb790b40b08" },
                { "ne-NP", "c37128658adea2ee37ec5869a894887e2023570310bfd75c18a9ab229756d6fb355bc91914c931df3668d654defdd76e3e1f2be11b3e121e0ed0d7d7413f4e06" },
                { "nl", "f9612ccbff9db89f0dbe4312bfbeb62dd0bba8e20f0ae6b05e7f9c29cb9b11b73f6b284b61e6eefadfe3f5e07b20f468a150a5fd7398b066aad370ce6bd63b95" },
                { "nn-NO", "f04db8e89d0861fa7eae3954d564e44b2464a0fda34486e5d013c0dc63cdc9cb0d9137e12cf4f0f2cda91d44f306b0fba714b17981c97ab4f21a7e52217067e9" },
                { "oc", "f78cc1c8498262212e8d7c74c71ce85cf94e77b1cb3d018ab54f02b8a55efaade9e222f310c92dac1b97517eea360088f620e58a5c3eb51935d0525f9fb3440f" },
                { "pa-IN", "269f2c651283f9e2295707e2b40d67ab4a6d4caf23fe83b4e993460810777edd64ca0af4374459c5433b8f9c16ce4cd8a5ef2a83a1517f4128dc720b22b9e5b5" },
                { "pl", "89a6a8a5f0831de679f881c603e4e4ae71b036bf60a90b07c0cb35046f70e47e9811f5c24adade79bc21470e664d4e781b7cf76414f4fcc2e89d8413ce154fdd" },
                { "pt-BR", "f2ad1d621fa4ccafc79799e1ed8522b8f585947b45aa337670c833f0da9fe7b3d134a08a8ebfb5fb7e9f3d6c85cb9786e017e29cbb24d06dea3563b86107d7c6" },
                { "pt-PT", "0b6414d8a4fdb91f6828ae68ef6a1eee6f73b66476b380fcdbf0a86d4b5db2665da4d2b5d32bd68d3d5cc2c6517eea0405fab5e8dcb7746bba60892a44e0bdb5" },
                { "rm", "2da1a55d3c8cdfc89f0e907e4cb08eb96268fc8d9570a83dfc55d872e5ac3bd081ca9316faf5db5f728ad282bae8e0283f91e61b029578a45cb8074f77524d8f" },
                { "ro", "686d4b74638015778a726c7de3f83a00e69f8e99f42a61243e650c34ffcad422637e1e037c28c33d4ec81aa92df4b914fa231e011a5c17ad280e868c87d4823e" },
                { "ru", "8beba582712d802c2753e354db6c31c6759b57767460b8930b4e435dd1d0694fc0ae52096b7d106c09439d6f48848dfd276cb9adf29f4e5a637cbd475c00168f" },
                { "sco", "06bff309247b6eed09514bb133e6384f1829feca3a37a7f96b467025e97ff15428e8ffeddc0ec933f1020a25fb0ab53cb5110ee8e1f6d11ca6127df4eb10fdc3" },
                { "si", "c7ff16530938b9c0d59af8e28b6b077f2ede823ff37042cff6e9b6792c151f4b82a9f61e2596db9425bb7b73dfa4280a297e6efeb0fd4e5a6fd5d4e2531bf419" },
                { "sk", "217694ef562bdb20bb6591fe8a0536e5f3ad134fda36fd1b72363724a321b8a06629909d5f8e95751f9f9a63169a7af463fee397088a142f2d9e2573bccc56ba" },
                { "sl", "9c9bd0a43bf3bb986ab5c966c764e35ebbedfbf9ae54c2bf8d616ee5e5732f8bea4a35e443a9b6be8c4bc1cc0b20dcdb3426fe44780659bded82191f8c82c923" },
                { "son", "75e3e065ba6423d47ef2ad2eb4a19469716e51a31e0623ab96f6184e96c1ed395af5140b1f95f0f2188ae5a3827e883f5922348dd95d6a9dcd845caf6d3faa3a" },
                { "sq", "378eaa68e1075e1c6e5ae5b8d4df00b4670e4f4ec007987d8d6f3ae9a3b4b9164e30b8edec3799b5922f4ce3a101e2fe7c9c76856d576e77f32dd25ab0b099bb" },
                { "sr", "f216e85ff3228de469eb756deff3fc190049d43ee61b6e395daf9c93a262bf86c6f00d68358ffe113bd812de0fffeae68c75fcf38a7c46b65e8f52038014f3da" },
                { "sv-SE", "9efd19e1dd212eeaee1104787b28d20fef3069648fb1bd41475830299ca6eaa536f63f9e97d35927cbc704816e91d83c81d0e03ca77f3a47ac428780ec2cf6e0" },
                { "szl", "3a0b9dcfd30e02490bd3f216c1156abe4e257def03eb96872ab4df4e0f71e6168c83c50a439062adce88f9a57b7fef247f29fde100b93e5da73dbab88d102f9d" },
                { "ta", "4d2bfc09e76424d602e2090ca9060baac79d899342c1ffef89a6a2a37573070853708f1dc58b08800a2f7642ff0cbfb25d9757e121e94569e45dc0ad3c216a25" },
                { "te", "d8f5eb4bb1c56d764c6e01b41be5ca5fb0bb51b7b315d7d666c63a1ea05097b9eb36e73c31dfbe8669e9edc8c86f0066f212c77758d9ae6ca13b156123ebc5b0" },
                { "th", "7449bbb4adbf07a20c6bbf57341a2a11c0639759f6efee059d1e05c63c50d9544185b99f91405743a0c83b82e5b3c321b4aa00db126c8dbfcbe3007998eecee6" },
                { "tl", "493cafac311b267698f7ce52df37c9ff449095daa91cc2b50f8e896e5de9aebc20546708805c0123ad16db63d0fdd809a4d6eedf1fc737e9617d3476fd9aea1b" },
                { "tr", "041220ba37318831aa09c432282cb1bdc4f5b35f2e1c61073d52bb8b652005ad8a3540585af9f3e9b849c34ec76c7d9e7503ed736f9b22d3429f3915b979e9d6" },
                { "trs", "367405cee970446576b8bcaf16f187317826f6dd3808641918c4974d6584a060366c37281ab3d5a9106284542f8bc6aa5aed3affcaa578f485bd2561b8acf06d" },
                { "uk", "318ac2b91bb9552e4d2ea6b442f45b23e27a3e148b50fef78ddc73bca2ff5c9f0153b2e7e6a7687bc10a3ac9ad86035e76095750d2d3451d48584abb90c8e0f9" },
                { "ur", "b8cde5c66a302ce3663b750f1aa46179b3a4e7424e35aec81b4500ddc2bf82cf2dbcfab8ef56b3bd2e930df33c6d7914451b9aafc10146b0a65df328078b3cd6" },
                { "uz", "b4dc75bb4cd0fd67230932480d1bf384685b177d884ad056fa8062ca41010ab9b1b4b08bfb837e8045871fb8b412ef9bbbfaa37ffba4273be005c9722610aac6" },
                { "vi", "32542d0aab0eec94a7c44b0aecaf04637775a986bc6ea4480c47482044939a2f3bf2139eaa00b4b5eb66db333755a20cf7ed5c682d121f6b332849d2d9641744" },
                { "xh", "8915156a1d53f21e911aa42296775ac82f8796d9e7a5f91ee5a669371a9769651c065de39465fc21c2cdd134bf2f64032442f78fbd3d7bb2cb215b3b386b26ad" },
                { "zh-CN", "c791c9e9eb005786fb9f4425dff7b9e0466cf2072196658c3d4ff4858b41361ced4acc59824d7e7cf93c955b0f13ae6a7e4205a65c68ea3b733ad5215dca20a2" },
                { "zh-TW", "894b6d05d1f39a23172ca95c58e9b40cbfbf96638c2bb6c949fff7d0619fb16df5331fe03aa141cf14a32a6d19cccef1b63b69b6dcf47d736c82966f2b0205df" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/108.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "11674985e83a5ba24e227a260a4584659582036f674109c8f352cf74d65764313e001acd3873401b33077c9e16f6a86e4558fb2d245ae5fdce1b2b3059447769" },
                { "af", "c311bc784b0b18ebb8534e05d19faa368ecfe28d254bb53d0af60671c8d5062102f06d5a3d9cdda9bfd49b4faa13b4612c7c6a1773791b1e61abd349319c70cd" },
                { "an", "abf44df9f9780715680cd8afdcd1b3e4fd306e6ac5ea7b8e6e3a9dda8866ba2e660fc431ffc5103fb96b2c5a6a61816a1a91837b08dfb9610250eaf06381de53" },
                { "ar", "033c0638452fd5c46dd3cf4cd13844175846eac6b6cc8c5460061d827f1e143dcb5e3710a0ee4e154e8b77be86a218d1c986635c0172e4286c6257ad27df7f81" },
                { "ast", "d3548814d7eea4780db0b91a672d40c49893c17ef9feaf658a187b0cd13d66016a10d13b33191da5960a14ca48e80e22853ddf55681a911fcca341906a2b8507" },
                { "az", "f5d9fafbdf1ca9305a07364c2687b8aa3cc082152b356374fe024de97205a1384fff00f23e837c1372b32d83eebc2a814a311684815c7082b1d59f0aa1ae654c" },
                { "be", "4ae3aabaa46a6970c665e692582b64fc2348f6d18db0bb7a2c536da53d3370d6ef4129dd9153c495d33a8a12bd7f3e53277d8642058b70692b2fbc9aea0ded8c" },
                { "bg", "426c3c45b09e0d5e112cad90fcb703047f927666c7902cafa9873e3f527f830d45278005cbe804d9f60186959c09a12eaaaa8b4a61a5e2403c46bd4dcf2aff63" },
                { "bn", "5abcd99a97bc3f86acbfc45cd72c722842d7d1dff678ffed832da71620352c1c7de3f7f8b6da29dfad75f5b5a397bbac97b30ad233b1329a756b0dbae1f959d0" },
                { "br", "66bfc5041c48a3336d68c7f421118a854566871de4d3a0bceae09aa8db54295880dfdecf82fe8d23b825cb7d251db344d84101f3b6b0f09509315d50732e5eff" },
                { "bs", "834eeb4c845f45a4306eb7bf9138ff87a74d189793034f03e99616a696522236987f42aff5fe1063e516d56dad2548f65605e8f8e003696a923ec877a72ba63a" },
                { "ca", "ceb64573281b50897ac6d7d90795dc01c9f900271fe6f7747cb1d5d9f2e0736ded52cee4acaee0cfac9187b14f2f1edd43d0e34c9ebfe733a6e5b3cd255436fb" },
                { "cak", "08a5f643af202e8faba25efed0f554a8c430e26a89155d51cc47f9e27459f69ed6319ac69b72de031e7db1d4b723edfaf58ec3c31b43a158ab9789697348a5f6" },
                { "cs", "072a0427b460d63f12a1776c8798496e28a1b9b3b281b2f28d04a21ac2625ad1661477f98e5f4ac666ef2b34092277726d52f4a81a12599e630fe77c19c31b38" },
                { "cy", "d8bc9bcb4b29070ee20e3e4332ef6a185005ecdeadadf3d765ac7a75f3c3984d171852f6638c0312738f66d7d00aa20faf738081e14ba466ce9081b268e46b28" },
                { "da", "0e989b0a0161a2bd455929269a47ec15d529b357b12ccaecd9b755fa281f147cc366aa9e04f95047c694b7768155cee09e670e598f239411f9ea1bbb793bf1a6" },
                { "de", "f247588d136a01d53d2a26d468014db3a738b083abe8f5b6c386949a513eebf01fbbdf89e5dfe64c30d35a43ff0195ae01e2d7f3cbb84190f87730076bf20a3d" },
                { "dsb", "3948a6da4e9fc7e152540b74a55c8de4b25284e45c29e64c244485a4c1f4503051fe39a4f88046d009792bf9003e3b7bd6402a36152f198cb2cb5af34b289c44" },
                { "el", "9ec323417e05fff76c37d9a088a0443ae4d11c5f04953288b4b8a13925f2bf1e59ec6214f00518824784c71f38eadeafda4d01b859e0b0051f58ec8ee1d45713" },
                { "en-CA", "90d04a283149300e20087adfa4bb6664891455d1c32219ad91e89033f6d651877aa39d2c5cb68d78f97008a25622e95f0a2eea54984d96579f4ef918ee69bd3a" },
                { "en-GB", "dd66602a61d6a38444ef6e3af63a3411d1e9006c24346bbe0aa70190be617fcd17baecd6fffaacab87fa8114270641dc1b5745714b5260612395525cb60ff201" },
                { "en-US", "95190c69409bf83e515ef9faa9c51ec19a613ce41dc42acbfdf70dfa559fdbbc28ba9f5123cb40069cf21485ba965a02f35fc615f2a498d373cbd13d2e1a2f5b" },
                { "eo", "5bf60e28d7713bae16a893195b2444f3416823b0ecfda10485a6e78eaa31f90a5b65a0718f77952e506e99b88cf9301ec29b07ed3599c21573e371212f6f5e83" },
                { "es-AR", "56fb012f7a66d2c3559b173854ff06103061a49b0119088ceb49d517e6329254f62e1c83486a97dd5081f00260d0b4665ddc1ba64b0950092b75d1e451ca60f2" },
                { "es-CL", "96757f88c220fd7226fc07bda850f05e5ba2c9559d699827ae8ff2d150a29e2e61919bf62e0973b451cd0bb10b53654d90407e539e5500be44b66a5c15661c31" },
                { "es-ES", "918a45346497333a826c8fe58a45119090cd94e88d7c060923b9e606ea732d227458de4e545022f713b52a7942febe0e1c116afdb25628945b59875be2cde8c5" },
                { "es-MX", "ead92ef5dc2a0b021e25d8da91be4658fa1bfdbaa65a49924c8cdaac5ed3c2ca545067dbf9aa43763c6323239529efc987d5cb0444b21c2804a587ec93df5062" },
                { "et", "8f941071165da21c32a6f5f613ae9759a12098cb5eb2f43f285a7c1f5dde5bfcd9fddab901825660007ed017b5e6f74a2db2185ec4670af278e28cb80170abd4" },
                { "eu", "04aafb4d39738dccf31b2bac7f2b51d2c4f1958cb401cd4785134eab1a144bf629cd7b77a1fa68418bbbf4acd5acffd36735d547525168d828edfc13edc1d1e1" },
                { "fa", "928bb4b27e55fa63de6c38006d02a7dce9b6031a9695ae1119c94ea025d73b32c0fad42c70e8baf630ff657d1a5965880f9489bd801a896210fb8e02be348d9a" },
                { "ff", "49aa92b89b71d2eb2c829c4a004ca95a96ad48b94c273f29461aa513e0dee29a26a017393fb5bd391f3181392e159e2bc802cbbd77a5c9d0a30d33af3675109d" },
                { "fi", "435e0b2c88cd101f6d761fd662ef0d772d6de0977f6f34adeb407892f97ed55d2a0831d6a0e8b08ee9b91bd1f66d9154663c0b564a9c9a02e712e0d04f9201ab" },
                { "fr", "147f7248c8375678ef49dcfea6758b15050f369f371d03cc23fda4a6ae92e0dbc3ae0859b5b1e0b8de6d91a9adb3089fee2a55418c7581a060930ff90387e6df" },
                { "fy-NL", "459781cc367fe799f94564269ac9f8fdb1a8195d9a57969af9481691a0f9e8c13fb583654bdb47f47ed0d10567b99461687d5625b9ca683387d03c8cada251c3" },
                { "ga-IE", "20fd7605a634e7c905cd8a88187b54aeedf8e040afd778b8f5708b59a16eea4ddad4ddd77d4c3c8cee00eee83f118dffa90bbc61262556e682b22d4f006e8446" },
                { "gd", "03a1c0f364c07d470296f3cd8af95a40835f3332a6cd9c22f4ea02b0657b303a5be1d599d0aa073a36d360304b2d35a84ca06bb2cbe5d13610ffcdf938864ee7" },
                { "gl", "3a1603eb21dea98da50523e6b6d3a0febbe4e41f13522870e5718d2064c4ea454b4cc49fa50b847297ba4ce63c0c23837a40e6b0713a9063f92a6a5f43ab1fea" },
                { "gn", "302e52e6fe87b099e90fcedcc99cde63d6fb7cf182464884d13015ebe994118e62430e123ef70f4c99cb6de00dd7a46f6e4da208df63f339259d430348b41724" },
                { "gu-IN", "524d0395231868bd849da84693fabba180ae6af8868654be5d753b46cc96a63f5302b65eff4b2a86d301385fa5c4a0388573449bc2695a46cbc4a778083ae0ef" },
                { "he", "e2fb062e5aa80fd4192e9e14ac9d2de42c4eb75b70bf392ec6db78562d64ca1f92613b5044bdb1627f852084b3103ad7f95cf3f3bb8f4f8b23c5718f99226120" },
                { "hi-IN", "730b1cc17063e6fff4e1784e1283276137d027595083d19c885f011651947b483b7093f02b0b6e33c5142453c8bca4cda1e38526371b777261e869b6db2861d2" },
                { "hr", "d3592d6732027703b6e6db90fff54a7f7ab3c698c0da919ffa3d9a18758d3a9f0e3f63a3bce2f55de4ff86743e544121ffea8ad908e9625633cb7de73fcbffc5" },
                { "hsb", "1a7b1e5e4817dc5de3874d65604e433d4d04e6f2d6d931a0c7e1e4692066b354d5afdfe4cd97b0d4ca39a8302ce879c939f1d23405993c35e3580df9c0a93f78" },
                { "hu", "ada23397d2e2699e62607103a7536281754111eec3b2b232541b57a4ff6c5710e281428c6011065f4e91b5a44ac4edf3784cc7b32bb13029d6baecaf51cd9258" },
                { "hy-AM", "9ae06bf1839c79bc01f59d3d832ea5025bd7b26b6a0f77a0d793dee3ba875fb430d7ff74eb18d7eda0c98e0a43ed3ddced5cbf4abd65d2a810ddd20b52eb145a" },
                { "ia", "2c80e62a3d9603b97eb9657419825b6836cb852a63e5e6cf60a167b309eacf282ac0d2d4c7830cb8c03d9bab25c56bb768b83de0f8450bfd82e690dfe896f7b4" },
                { "id", "563c3e996df316e53cb7b850f3fd8b06af292f87ca4ca488ce1b873edc3b528faf84e38eac933a55516aa1f2c3548c1efde9298cbb36ff5ce2ad52eaac166765" },
                { "is", "b862979e0847c9463f8c6334bdb5f81dbd232e79ed922aff0626c73466592aad109455e7ef4f65931d1476142fbeccbfa8dda8cac0f92b2aa504f8667fa236f7" },
                { "it", "865824318fbc2fe69002d7b5b9b70854b8e067b3d753e3f50a27d009a8141e083d823e70361485c5d44afcf8d138c50a5032c750dd565b137bf3c742f41e7da7" },
                { "ja", "98546dc5feab16151061aeb37e7111c2437972ae433391f634d8d699468301d8ce31ca0885f8088bdbaca67cb016898cbaa497fe2863ce58ea131a568f3f64a8" },
                { "ka", "6fabe87423592e8523770ac604d7cf3b613d04f2a5e9e256669aa4482c190b1ba2c9a0ae9e48266f7fa62ec45356cd67fec9c5daee0faee1a958e69d072c615c" },
                { "kab", "2ef1ff694e4c79006d1be86ced2e92757898a982bb79ff7e65bf54108aa581bfa8dc62f27b7a0ad07392cab3e58537d9cbef6d11803d78c10cff24811160fa46" },
                { "kk", "bd0e8cbfda0c780550ff2fd95ea96239e7cd349fce2d4f62c50fc8108bd0b9e0a75b2e2b354a25701278b680fd4ac13a705fc5b37611031b5cbb0c9e64b0a7f5" },
                { "km", "ba71d4e42a356474d9c30ec33359d209a5c77f0d2a46017c2929279021885db3b873c5aa4d6bd95b054ba57e2f06e57d9384906f7802bbd378ef6abfced81d3e" },
                { "kn", "c0d7e8c69d941bee070089cbf339cdd882ac23acb85f6a161921c4abbeeba715476f4aa4c3b4957a787e9c49e7d0e1efecda552d1f46093e8e52e2a29010d534" },
                { "ko", "1484f2171208fcba402739219d253c75b6cc9ada87d5e844e967357998441c86c6a83376ca629692dda0381fefaafd42f55b1beae15e10f77ba160c925e5b0b9" },
                { "lij", "9ac6c7f82ab63ae3b3af44d4406868d3edb5da9e827c39896e5559aef7c8a51e5ce269c35f862ef6e98ac874f87c4525097a4d7f974195788749f728807888b1" },
                { "lt", "84f8e8e6dbc71c28c84dc2ce29c58910c34cd98ab509e025238181387ba9c4e749c56b57381b617082c1cbe6e951f556cad34ff449bf1ea1d5627ee682077689" },
                { "lv", "7a84ca778eeb31be162350f6eb00c7d958343615e8ff74ac0428346baf0b18a8d57d2be6ed8adf1ed415552ab3c832b2909b929cca4f1463f9f838b34eb05171" },
                { "mk", "ba35212ce3e1d9b58c1e4c399ecc11298f8161ac4ff5f7524a57833a824cf9fa9a056388d0395fb92b52ea041f32e55517aefc79e783e9777bf16f3685123524" },
                { "mr", "59f3fce98f5da0adce361b5fa7482f7e2f998807757a612953ffdf6bb9ba8f6cc995a7a67726ee235f72e91d2548ec56a6001c9ddabf43bc97c6c8472acc40a2" },
                { "ms", "627800b5d4fb340681f33c4218c48ae3fb31624e908656f4a371a60b91ad3e8b44a412f8048fde4cd4ee065e5bb078bf85d5854f5a04ec27878354eccbaf001f" },
                { "my", "c2bbccfbc013f2d4ecc078b3babb60a95a7de96161f4e95bda9d943f5119994d1b891aa31120f7edbb2c9aafbc4e50815802c65dde35ff8b66ba51ed25f526da" },
                { "nb-NO", "b0b1f39b1b64ba1959b97dc0545acfff84af8c42f30cff324953a81ed6d2e00721cd3702895bc61fe700270af0443d25b74ac54c573da75af24e4e2127d5fc24" },
                { "ne-NP", "a153d1884baeae9339f8baae92db6665704348beb46e9f0bf23be62bd96eed6c793dd54c1e349c6e66fb2ff3fe98efa277160860f1c557c567d061582b160091" },
                { "nl", "470de65a280ec16d322ddd00ffe5059089e888892e2aec7fa9344eb4dddd456bdfba87b834c536bbe29781f49c239dcf50df16ee15a9ea38868b058791c5ce9d" },
                { "nn-NO", "7e57e63580959b43493b1daa164467e56ada8321e0b908cbb96394619d3d59904f017fd87a6326adf9e81f52b9b85406bf204cd497a1b2a0c1dc80cd2edd3a2b" },
                { "oc", "6a66291b5783c367b838b66807b4cdeb7eb3b17db2e3d916a2839856843e521eb4a9450e1e4fdfb0b0a8e96fc0feb79579158e19ef93cc580f9fa0b1b963bf18" },
                { "pa-IN", "4d2f5be010bd0e00616096b90367ad772a5ec7051d8fc8e406f1c99e8c3d67350aa82f045fb4b9eabb40113274e9fea247a5128a75c73a6ad67d239c9b24fca2" },
                { "pl", "18e6af208b1096df2cc3a405b7e1111937381c365f2cffcd0ef323b0d84816c2178041c4998294714d8dccae47eef780f85be3ffca4ff07012c56a8565c60767" },
                { "pt-BR", "2663dcdd643316b657c24ffa178f3d440df1629d12ab1772e3f2ac5ec98f587bd042fd22f4a225347e66ee103dbefe0a7c3b0d245d464aa19000c4e52e681526" },
                { "pt-PT", "d18f107e51c024b41a00246e84fe802fa31bccc173200c5e45645f6ffb9cd19eab7be841dfdfa31ec5a617a6e25fb284fb781e3992f17cc78a06296f89340538" },
                { "rm", "fda4cf74526821d3804e5aa52d59c1d7f1047f80dc398777029d0aa635f2703b080c55a1d0c2069d3e1bb57708371f20dbc5f278c362a28b5af5f910000440c9" },
                { "ro", "879d96da812471e9dfc09f60b16dcd5025d2c851f37184041c8fd4eba0be303e41fefaf95dba74042baeafd85e16f0d1350399781a1af9beb559f697a26767fd" },
                { "ru", "da8c43919c2966b83f76e9c77167cf4c99127e7856cc3bc12ec1ca92fbad9eb4ec1dcfef990db3eeefb443014d18c22f554f0853707a9371d353bf2bc60639c1" },
                { "sco", "db71de3088ca0e4098076b450bd5fde893d4f45c093cae9e11ac62f1e133ee250dcc04ebac3adad5da2ac261f2d1fa248d57054e1a15297803cd5f7c7ae630a9" },
                { "si", "3f272f63c4a4dcc62b7faa83977c1be66c4dbc8b5efb0795ecba411ef127ee2294bbc43696d78c41c7d234a56985f27334efe91b79e6f5451ffd23a44c1c7ca0" },
                { "sk", "1bf8993183e6ca3865b6ee192a3461d834300c25b25d61805740bcfd3eeb55dd72298ee7a1b8206cbb0845b03ee6cc33a93c1dbbfcb6004e54a8c0c4f881a89c" },
                { "sl", "518f14fda16992e40eedbcba8cca39b18c69ca8dcbb3cd9f6dab2128ab48dcc4e2bda928cda16c743b0c7a5e2a19901f1c6209517e2b9b5c10b6b7dd44a61e1c" },
                { "son", "5e88bfe9eabb29614804680b378fc43972252764858ebc84a61bfaad2ddac0792aca0c61c17d154640aecd854d10b51b9a5421e19e67017f30a9688cfe0669fa" },
                { "sq", "f247711a816bba70bf5b74802b5cbc900575f502d1317f0910ce8d1b7a4aa332c45f7ea5211a1c51dce2d87028788fe891b60f741702704e31f196c0492fd896" },
                { "sr", "50477e830cccff8c556618eae2d45d3dda4e7eda66aa3a5dd88d7174dd7699021db99409bd0d3d720cb03989581e6ac08c941fae4612ddfac4ee657d25ecc92c" },
                { "sv-SE", "2551d2ed7bcf9c238a0f63c0b3e232edb75c1017704db0fd1743164fcb59b58a03547d659c2b345392944a3e6639c3a603a0ffd3c8ba60811f106e0c903a1688" },
                { "szl", "f46217ab5696f2f614ffc2a0b33680feeafbd39c19fc1a281fe55368e6a35e299036c2dec2ebb47a75b922e39c9e469d27a8298f4a55f841e31ac50a153991ab" },
                { "ta", "2f73d60afe77e96ec5c0a7ab37bb1170cff0db3ff5581588d6b137229a79ea6374cec8e75bd53c79f4a5404d85f61621f9dc904146b5bd2d7fd972ac376455d0" },
                { "te", "554aec0aaf8e8864dba8109b65750155adee898ce1a22414f51a5575bbb25013ccbbe4cd8d56f79534d1aba256237aa96693dc4200819145bcbf5894efe120d3" },
                { "th", "594a245e5fecafe54efb4d6457cb36d39c65d7d545eca63d5b6fcd468c725dc66ca1db7fa5b4c306eb1cb458d37634b869cab9ee34588a537608a3d42f3ad4ff" },
                { "tl", "2e2d1ab1ba098ca06fd73d4929e86f6db0f66e9458cb74e71f1bb8d28d49eedd7ff34001c122058cdfb00fcab8a8b551e3ff5cc70f67f96198b1e0bc6db9ab70" },
                { "tr", "6de6a124637cf76cd65270e75fa7936f71f911ec19af68334bd8b0f4b01d91fdffc05c9a52ab2b8689976b066c000f7150881af318a60074daaefdecb1f8723a" },
                { "trs", "ceb3c51e98e4269d9fa22fe1143a4d7c203e0cf9fcd69fbfd8559ef46d703c158fec7a6a7120e96b6fce911f6c3cf0a55d77f70a7bc790ba5a542ba0356749f5" },
                { "uk", "98ac4e0b8297ecb27a2bfb8a14871d6f3ff8cffc303d60ee478aba7b2bae950a039c924acb2a4d1f41975e0cd8765c5818983c87d158a62eeaced21bbf1a4760" },
                { "ur", "d9dfb41ca5318095ec70274d0e43e3d58e6ca3990c1337459ed675c1958e250652167edd6c3c3cbadeb14d34ed46c56104a0d16c03aeb0e764db72610172adab" },
                { "uz", "054d9cd37ea9d48186b0cbb414cbeb562bc3b585847f036cae3b23dd7f5fd0b4e08305062ce8701e79af399af79d5caa2d0313b4a5d45aa6d081112c92b79587" },
                { "vi", "e3b2c012624574d08ee1822b73d34d4e29828566a86e7c9ec938439a58a6e4e12521185af697eac450ec1244f1c41a63dc1398bb8381ac3f073439906b5e9ecc" },
                { "xh", "391b922e5e0f209c02c739c7fab66f1b5717c9bea5f3158fe174c6c3472945920659cb47702528029adf5e628bce3f7ae3722622a63a307ba2936c625ca2f107" },
                { "zh-CN", "8b08e84debc8f6642e4d5c21e2af63b4d86f502aef85510adc9121c6ac2ef12054b1d684358c0c17efa13a52e30dd504187eca92a0184b04e9254717e70cd971" },
                { "zh-TW", "61fa22312c1345dcb6cc4ffbe6c840a09971822813eda758e4b6d86e5a778afb76b156bd2aaf6d73a6e4109ba7e4189d854aaf26c194d37805e41b22b11eb19a" }
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
